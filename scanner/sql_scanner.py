# scanner/sql_scanner.py

import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from tqdm import tqdm

from .form_scanner import FormScanner
from .payload_manager import PayloadManager


class SQLiScanner:
    def __init__(self, url, max_workers=5, stop_on_success=False):
        self.url = url
        self.max_workers = max_workers
        self.stop_on_success = stop_on_success
        self.payloads = PayloadManager.load_payloads("SQLPayload.txt")
        self.vulnerable_params = []
        self.vulnerable_forms = []
        self.lock = threading.Lock()
        self.stop_flag = threading.Event()

    def inject_into_url(self, url, param, payload):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if param in qs:
            qs[param] = [payload]
            new_query = urlencode(qs, doseq=True)
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))
        return url

    def scan_url_parameters(self):
        print(f"\n[+] Starting SQL Injection scan on: {self.url}")
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if not params:
            print("[-] No query parameters found to test for SQL injection.")
            return

        def test_param_payload(param, payload):
            if self.stop_flag.is_set():
                return None
                
            test_url = self.inject_into_url(self.url, param, payload)
            try:
                resp = requests.get(test_url, verify=False, timeout=5)
                if any(err in resp.text.lower() for err in ["sql", "syntax", "warning", "mysql", "error", "ora-", "microsoft odbc", "postgresql"]):
                    with self.lock:
                        self.vulnerable_params.append((param, payload))
                    if self.stop_on_success:
                        self.stop_flag.set()
                    return True
            except Exception:
                pass
            return False

        # Test each parameter with all payloads using threading
        for param in params:
            print(f"\n[+] Testing parameter: {param}")
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(test_param_payload, param, payload): payload for payload in self.payloads}
                
                with tqdm(total=len(self.payloads), desc=f"Testing {param}", ncols=100) as pbar:
                    for future in as_completed(futures):
                        if self.stop_flag.is_set():
                            break
                        future.result()  # This will raise any exceptions
                        pbar.update(1)

    def scan_forms(self):
        print(f"\n[+] Scanning forms for SQL injection on: {self.url}")
        forms = FormScanner.get_all_forms(self.url)
        if not forms:
            print("[-] No forms found on the page.")
            return

        def test_form_payload(form_num, form_info, payload):
            if self.stop_flag.is_set():
                return None
                
            action = form_info.get("action")
            method = form_info.get("method", "get").lower()
            input_names = [input_tag.get("name") for input_tag in form_info.get("inputs", []) if input_tag.get("name")]
            
            action_url = urljoin(self.url, action) if action else self.url
            form_data = {name: payload for name in input_names}

            try:
                if method == "post":
                    resp = requests.post(action_url, data=form_data, verify=False, timeout=5)
                else:
                    resp = requests.get(action_url, params=form_data, verify=False, timeout=5)

                if any(err in resp.text.lower() for err in ["sql", "syntax", "warning", "mysql", "error", "ora-", "microsoft odbc", "postgresql"]):
                    with self.lock:
                        self.vulnerable_forms.append((form_num, payload, form_data))
                    if self.stop_on_success:
                        self.stop_flag.set()
                    return True
            except Exception:
                pass
            return False

        for i, form in enumerate(forms, 1):
            if self.stop_flag.is_set():
                break
                
            action = form.get("action")
            method = form.get("method", "get").lower()
            action_url = urljoin(self.url, action) if action else self.url

            print(f"\n[+] Testing form #{i} with action: {action_url} and method: {method}")
            
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(test_form_payload, i, form, payload): payload for payload in self.payloads}
                
                with tqdm(total=len(self.payloads), desc=f"Form #{i}", ncols=100) as pbar:
                    for future in as_completed(futures):
                        if self.stop_flag.is_set():
                            break
                        future.result()  # This will raise any exceptions
                        pbar.update(1)

    def scan(self):
        """Scan for SQL injection vulnerabilities and return results"""
        # Clear previous findings and flags
        self.vulnerable_params = []
        self.vulnerable_forms = []
        self.stop_flag.clear()
        results = []

        # Perform scans
        self.scan_url_parameters()
        self.scan_forms()

        # Process vulnerabilities
        for param, payload in self.vulnerable_params:
            test_url = self.inject_into_url(self.url, param, payload)
            results.append({
                'type': 'param',
                'param': param,
                'payload': payload,
                'test_url': test_url,
                'severity': 'High',
                'description': f'SQL injection in URL parameter {param}',
                'remediation': [
                    '1. Use parameterized queries or prepared statements',
                    '2. Implement proper input validation',
                    '3. Apply the principle of least privilege for database access'
                ]
            })

        for form_num, payload, form_data in self.vulnerable_forms:
            form_name = f"Form #{form_num}"
            results.append({
                'type': 'form',
                'form_name': form_name,
                'payload': payload,
                'input': form_data,
                'test_url': self.url,
                'severity': 'High',
                'description': f'SQL injection in {form_name}',
                'remediation': [
                    '1. Use parameterized queries for all form inputs',
                    '2. Implement strict input validation',
                    '3. Consider using an ORM with built-in protection'
                ]
            })

        # Always print summary with colors
        print("\n========== SQL Injection Summary ==========")
        if results:
            print('\033[91m' + "[+] SQL Injection Vulnerabilities Found:" + '\033[0m')
            
            # Group and limit form findings
            forms_seen = {}
            param_findings = []
            
            for finding in results:
                if finding['type'] == 'form':
                    form_name = finding.get('form_name', '')
                    if form_name not in forms_seen:
                        forms_seen[form_name] = []
                    forms_seen[form_name].append(finding)
                else:
                    param_findings.append(finding)
            
            # Print parameter findings
            for finding in param_findings:
                print(f"\033[93m[Param]\033[0m {finding.get('param','')}, Payload: {finding.get('payload','')}")
            
            # Print form findings with limit
            for form_name, findings in forms_seen.items():
                print(f"\n\033[93m[Form]\033[0m {form_name}:")
                # Show first 3 findings
                for finding in findings[:3]:
                    print(f"  Payload: {finding.get('payload','')}")
                    if finding.get('input'):
                        print(f"  Input: {finding.get('input','')}")
                
                # Show count if there are more
                if len(findings) > 5:
                    print(f"  ... and {len(findings) - 3} more payloads detected")
                    
        else:
            print('\033[92m' + "[-] No SQL injection vulnerabilities found." + '\033[0m')
            print("[*] Note: The absence of errors doesn't guarantee safety.")
            print("[*] Consider manual testing or using advanced techniques.")

        return results