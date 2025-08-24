import threading
import requests
import signal
import time
from urllib.parse import urljoin, urlencode, urlparse, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium.common.exceptions import NoAlertPresentException
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from tqdm import tqdm
from pprint import pprint
import re
import random
import string

from .form_scanner import FormScanner
from .payload_manager import PayloadManager


class XSSScanner:
    def __init__(self, url, headless=True, max_workers=10, stop_on_success=False):
        self.url = url
        self.headless = headless
        self.max_workers = max_workers
        self.stop_on_success = stop_on_success
        self.lock = threading.Lock()
        self.stop_flag = threading.Event()
        signal.signal(signal.SIGINT, self._handle_sigint)

    def _handle_sigint(self, signum, frame):
        if not self.stop_flag.is_set():
            try:
                print("\n[!] Ctrl+C detected. Gracefully stopping threads...", flush=True)
                self.stop_flag.set()
            except:
                pass
    
    def _init_driver(self):
        options = Options()
        if self.headless:
            options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(10)
        return driver

    def scan_reflected_xss(self, payloads=None):
        forms = FormScanner.get_all_forms(self.url)
        payloads = payloads or PayloadManager.load_payloads('XSSPayload.txt')
        findings = []
        local_stop_flag = threading.Event()

        # Get baseline response
        random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        try:
            baseline_resp = requests.get(self.url, params={random_str: random_str}, timeout=5)
            baseline_text = baseline_resp.text
        except Exception:
            baseline_text = ""

        def is_payload_exploitable(resp_text, payload):
            # Normalize the response text for case-insensitive comparison
            resp_lower = resp_text.lower()
            payload_lower = payload.lower()
            
            # First check if payload appears at all
            if payload_lower not in resp_lower:
                return False
            
            # Check for common false positive patterns
            no_results_phrases = [
                "no results were found",
                "no results found for",
                "search results for",
                "sorry, no results",
                "try again"
            ]
            
            # Skip generic "no results" pages UNLESS we find actual script execution
            has_no_results = any(phrase in resp_lower for phrase in no_results_phrases)
            
            # Improved script tag detection that handles broken/partial tags
            script_patterns = [
                # Standard script tag
                r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',
                # Broken script tag (like in the example)
                r'<script[^>]*>.*?' + re.escape(payload.split('>')[-1]),
                r'</script[^>]*>.*?' + re.escape(payload.split('<')[-1]),
                # Script tag split across other tags
                r'</?\w+[^>]*>.*?' + re.escape(payload) + r'.*?</?\w+[^>]*>'
            ]
            
            for pattern in script_patterns:
                if re.search(pattern, resp_text, re.IGNORECASE|re.DOTALL):
                    return True
            
            # Check for other dangerous contexts regardless of "no results" message
            dangerous_patterns = [
                # Event handlers
                r'on\w+\s*=\s*["\']?.*?' + re.escape(payload),
                # JavaScript URLs
                r'(href|src|data|action)\s*=\s*["\']?(javascript|data|vbscript):.*?' + re.escape(payload),
                # Attribute injection
                r'<\w+[^>]*\s\w+\s*=\s*["\']?[^"\'>]*?' + re.escape(payload)
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, resp_text, re.IGNORECASE|re.DOTALL):
                    return True
            
            # If we get here and it's not a "no results" page, consider it vulnerable
            if not has_no_results and payload in resp_text:
                return True
            
            return False

        def task(form_details, payload):
            if local_stop_flag.is_set():
                return None
            try:
                response = FormScanner.submit_form(form_details, self.url, payload)
                if is_payload_exploitable(response.text, payload):
                    if self.stop_on_success:
                        local_stop_flag.set()
                    return {"payload": payload, "form": form_details}
            except requests.RequestException as e:
                return {"error": str(e), "payload": payload}
            return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            with tqdm(total=len(forms) * len(payloads), desc="Reflected XSS", ncols=100) as pbar:
                futures = []
                for form in forms:
                    form_details = FormScanner.get_form_details(form)
                    for payload in payloads:
                        futures.append(executor.submit(task, form_details, payload))

                found = False
                for future in as_completed(futures):
                    result = future.result()
                    with self.lock:
                        pbar.update(1)
                        if result and "form" in result and not found:
                            findings.append(result)
                            found = True
                            if self.stop_on_success:
                                local_stop_flag.set()
            # Do NOT break the loop early; let all futures complete

        print("\n========== Reflected XSS Summary ==========")
        if findings:
            print('\033[91m' + "[+] Reflected XSS Vulnerabilities Found:" + '\033[0m')
            report_findings = []
            for i, result in enumerate(findings, 1):
                payload = result['payload']
                form = result['form']
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                inputs = form.get('inputs', [])
                data = {inp.get('name'): payload if inp.get('type') in ['text', 'search'] else inp.get('value') 
                       for inp in inputs if inp.get('name')}
                
                affected_url = urljoin(self.url, action)
                if method == 'get' and data:
                    affected_url = affected_url + '?' + urlencode(data)
                
                print(f"\n[!] Vulnerability #{i}")
                print(f"Payload: {payload}")
                print(f"Affected URL: {affected_url}")
                print("Form Details:")
                pprint(form)
                print("\n")
                
                report_findings.append({
                    "name": f"Reflected XSS Vulnerability #{i}",
                    "severity": "High",
                    "description": f"Reflected XSS vulnerability confirmed with payload: {payload}",
                    "poc": f"Submit to {action} with payload in any text field",
                    "remediation": [
                        "Implement proper input validation",
                        "Use output encoding when displaying user input",
                        "Implement Content Security Policy (CSP)"
                    ],
                    "impact": "Attackers can execute arbitrary JavaScript in victim's browser",
                    "affected_url": affected_url
                })
            return report_findings
        else:
            print('\033[92m' + "[-] No reflected XSS vulnerabilities found." + '\033[0m')
            return []

    def scan_dom_xss(self, payloads=None):
        from urllib.parse import quote

        payloads = payloads or PayloadManager.load_payloads('XSSPayload.txt')
        popup_findings = []
        processed = 0

        def task(payload):
            nonlocal processed
            if self.stop_flag.is_set():
                return None
            
            driver = None
            try:
                driver = self._init_driver()
                if not driver:
                    return None
                    
                driver.get(f"data:text/html,{payload}")
                driver.implicitly_wait(1)
                
                try:
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    return {
                        "payload": payload,
                        "type": "dom-direct",
                        "alert": alert_text
                    }
                except NoAlertPresentException:
                    return None
            except Exception as e:
                if not isinstance(e, TimeoutError):
                    # Optionally log errors here, but don't print during progress
                    pass
                return None
            finally:
                processed += 1
                if driver:
                    try:
                        driver.quit()
                    except:
                        pass

        try:
            with ThreadPoolExecutor(max_workers=min(self.max_workers, 4)) as executor:
                futures = [executor.submit(task, payload) for payload in payloads]
                
                with tqdm(total=len(payloads), desc="DOM Injection", ncols=100) as pbar:
                    for future in as_completed(futures):
                        if self.stop_flag.is_set():
                            break
                        result = future.result()
                        if result:
                            popup_findings.append(result)
                            if self.stop_on_success:
                                self.stop_flag.set()
                        pbar.update(1)
                        pbar.set_postfix(processed=processed)

        except Exception as e:
            print(f"[!] DOM XSS scan error: {str(e)}")

        # Unified summary logic (same as Reflected XSS)
        print("\n========== DOM-based XSS Summary ==========")
        if popup_findings:
            print('\033[91m' + "[+] DOM-based XSS Vulnerabilities Found:" + '\033[0m')
            report_findings = []
            for i, result in enumerate(popup_findings, 1):
                payload = result['payload']
                vuln_type = result.get('type', 'dom-xss')
                alert_text = result.get('alert')

                # Build affected URL like reflected XSS
                parsed = urlparse(self.url)
                qs = parse_qs(parsed.query)
                # Try to inject payload into the first query parameter, or use 'query' as default
                if qs:
                    first_param = list(qs.keys())[0]
                    qs[first_param] = [payload]
                else:
                    qs['query'] = [payload]
                new_query = urlencode(qs, doseq=True)
                affected_url = urlunparse(parsed._replace(query=new_query))

                print(f"\n[!] Vulnerability #{i}")
                print(f"Payload: {payload}")
                print(f"Affected URL: {affected_url}")
                print(f"Type: {vuln_type}")
                print(f"Alert Text: {alert_text}")
                report_findings.append({
                    "name": f"DOM-based XSS Vulnerability #{i}",
                    "severity": "High",
                    "description": f"DOM-based XSS vulnerability confirmed with payload: {payload}",
                    "poc": f"Open {affected_url} in a browser",
                    "remediation": [
                        "Sanitize and validate all client-side data",
                        "Avoid dangerous DOM sinks (e.g., innerHTML, document.write)",
                        "Implement Content Security Policy (CSP)"
                    ],
                    "impact": "Attackers can execute arbitrary JavaScript in victim's browser",
                    "affected_url": affected_url
                })
            return report_findings
        else:
            print('\033[92m' + "[-] No DOM-based XSS vulnerabilities found." + '\033[0m')
        return popup_findings  # Always return findings