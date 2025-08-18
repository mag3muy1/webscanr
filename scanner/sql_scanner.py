# scanner/sql_scanner.py

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
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

        for param in params:
            print(f"\n[+] Testing parameter: {param}")
            for payload in tqdm(self.payloads, desc=f"Testing {param}", ncols=100):
                test_url = self.inject_into_url(self.url, param, payload)
                try:
                    resp = requests.get(test_url, verify=False, timeout=5)
                    if any(err in resp.text.lower() for err in ["sql", "syntax", "warning", "mysql", "error"]):
                        self.vulnerable_params.append((param, payload))
                        if self.stop_on_success:
                            return
                except Exception:
                    continue

    def scan_forms(self):
        print(f"\n[+] Scanning forms for SQL injection on: {self.url}")
        forms = FormScanner.get_all_forms(self.url)
        if not forms:
            print("[-] No forms found on the page.")
            return

        for i, form in enumerate(forms, 1):
            action = form.get("action")
            method = form.get("method", "get").lower()
            input_names = [input_tag.get("name") for input_tag in form.get("inputs", []) if input_tag.get("name")]

            from urllib.parse import urljoin
            action_url = urljoin(self.url, action) if action else self.url

            print(f"\n[+] Testing form #{i} with action: {action_url} and method: {method}")

            for payload in tqdm(self.payloads, desc=f"Form #{i}", ncols=100):
                form_data = {name: payload for name in input_names}

                try:
                    if method == "post":
                        resp = requests.post(action_url, data=form_data, verify=False, timeout=5)
                    else:
                        resp = requests.get(action_url, params=form_data, verify=False, timeout=5)

                    if any(err in resp.text.lower() for err in ["sql", "syntax", "warning", "mysql", "error"]):
                        self.vulnerable_forms.append((i, payload, form_data))
                        if self.stop_on_success:
                            return
                except Exception:
                    continue

    def scan(self, print_summary=False):
        """Scan for SQL injection vulnerabilities and return results"""
        # Clear previous findings to avoid duplicate/conflicting summaries
        self.vulnerable_params = []
        self.vulnerable_forms = []
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
            # Try to get form name or action for reporting
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

        # Unified output
        if print_summary:
            print("\n========== SQL Injection Summary ==========")
            if results:
                print("[+] SQL Injection Vulnerabilities Found:")
                for finding in results:
                    if finding['type'] == 'form':
                        print(f"[Form] {finding.get('form_name','')}, Payload: {finding.get('payload','')}, Input: {finding.get('input','')}")
                    else:
                        print(f"[Param] {finding.get('param','')}, Payload: {finding.get('payload','')}")
            else:
                print("[-] No SQL injection vulnerabilities found.")
                print("[*] Note: The absence of errors doesn't guarantee safety.")
                print("[*] Consider manual testing or using advanced techniques.")

        return results