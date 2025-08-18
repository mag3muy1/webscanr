import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
from tqdm import tqdm
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .payload_manager import PayloadManager


class MisconfigurationChecker:
    import threading
    def __init__(self, url):
        self.url = url if url.endswith("/") else url + "/"
        self.stop_flag = MisconfigurationChecker._get_or_create_stop_flag()

    @staticmethod
    def _get_or_create_stop_flag():
        # Singleton event for all instances
        if not hasattr(MisconfigurationChecker, '_stop_flag'):
            MisconfigurationChecker._stop_flag = MisconfigurationChecker._make_stop_flag()
        return MisconfigurationChecker._stop_flag

    @staticmethod
    def _make_stop_flag():
        import threading
        flag = threading.Event()
        def handler(signum, frame):
            print("\n[!] Ctrl+C detected. Gracefully stopping threads...")
            flag.set()
        import signal
        signal.signal(signal.SIGINT, handler)
        return flag

    def handle_interrupt(signum, frame):
        print("\n[!] Scan interrupted by user. Exiting cleanly...")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_interrupt)

    def check_security_headers(self, headers):
        expected_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        missing = [h for h in expected_headers if h not in headers]
        return missing


    def check_exposed_paths(self, max_workers=10, silent=False):
        exposed = []
        paths = PayloadManager.load_payloads('ExposedPath.txt')
        if not silent:
            print("[*] Checking for exposed paths...")

        # Get a baseline for a random path
        import random, string
        random_path = "/" + ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        try:
            baseline_resp = requests.get(self.url.rstrip("/") + random_path, timeout=3, verify=False)
            baseline_text = baseline_resp.text
            baseline_len = len(baseline_text)
            baseline_ct = baseline_resp.headers.get("Content-Type", "")
        except Exception:
            baseline_text = ""
            baseline_len = 0
            baseline_ct = ""

        def is_generic_response(r, path):
            # Always report well-known files if 200
            well_known = [
                "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/.env", "/.git/config", "/.htaccess", "/.htpasswd"
            ]
            if any(path.lower().startswith(wk) for wk in well_known):
                return False
            if baseline_text and abs(len(r.text) - baseline_len) < 20 and r.headers.get("Content-Type", "") == baseline_ct:
                return True
            if any(x in r.text.lower() for x in ["not found", "404", "error", "login", "forbidden"]):
                return True
            return False

        def check_path(path):
            if self.stop_flag.is_set():
                return None
            try:
                full_url = self.url.rstrip("/") + path
                r = requests.get(full_url, timeout=3, verify=False)
                if r.status_code == 200 and not is_generic_response(r, path):
                    return path
            except requests.RequestException:
                return None
            return None

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(check_path, path): path for path in paths}
                for future in tqdm(as_completed(futures), total=len(paths), desc="Scanning paths", ncols=100, disable=silent):
                    if self.stop_flag.is_set():
                        break
                    result = future.result()
                    if result:
                        exposed.append(result)
        except KeyboardInterrupt:
            if not silent:
                print("\n[!] Exposed path scan interrupted. Returning partial results...")

        return exposed

    def check_expired_ssl(self):
        try:
            hostname = urlparse(self.url).hostname
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if expires < datetime.utcnow():
                        return True, cert['notAfter']
                    else:
                        return False, cert['notAfter']
        except Exception as e:
            return None, str(e)

    def run_checks(self, silent=False):
        if not silent:
            print(f"\n========== Misconfiguration Checks for {self.url} ==========")

        results = []

        try:
            response = requests.get(self.url, timeout=5, verify=False)
            headers = response.headers

            # --- Security headers ---
            missing_headers = self.check_security_headers(headers)
            if missing_headers:
                if not silent:
                    print('\033[91m' + "[!] Missing security headers:" + '\033[0m')
                    for h in missing_headers:
                        print(f"    - {h}")
                results.append({
                    "name": "Missing Security Headers",
                    "severity": "Medium",
                    "description": "The following important security headers are missing.",
                    "poc": self.url,
                    "remediation": [f"Add the `{h}` header." for h in missing_headers],
                    "impact": "Lack of protection against clickjacking, XSS, and content sniffing attacks."
                })

            elif not silent:
                print("[+] All important security headers are present.")

            # --- Server disclosure ---
            server_header = headers.get("Server")
            powered_by = headers.get("X-Powered-By")
            if server_header or powered_by:
                if not silent:
                    print("[!] Server information exposed in headers:")
                    if server_header:
                        print(f"    - Server: {server_header}")
                    if powered_by:
                        print(f"    - X-Powered-By: {powered_by}")
                exposed_info = []
                if server_header:
                    exposed_info.append(f"Server: {server_header}")
                if powered_by:
                    exposed_info.append(f"X-Powered-By: {powered_by}")

                results.append({
                    "name": "Server Information Disclosure",
                    "severity": "Low",
                    "description": "The server discloses internal details via HTTP headers.",
                    "poc": f"{self.url} - Headers: {', '.join(exposed_info)}",
                    "remediation": [
                        "Remove or obfuscate server-related headers from responses."
                    ],
                    "impact": "Could aid attackers in fingerprinting and exploiting known vulnerabilities."
                })
            elif not silent:
                print("[+] No server-identifying headers found.")

            # --- Exposed paths ---
            exposed = self.check_exposed_paths(silent=silent)
            if exposed:
                if not silent:
                    print('\033[91m' + "[!] Exposed sensitive paths found:" + '\033[0m')
                    for path in exposed:
                        print(f"    - {path}")
                results.append({
                    "name": "Exposed Sensitive Paths",
                    "severity": "High",
                    "description": "Exposed paths can leak configuration files or admin panels.",
                    "poc": "\n".join([self.url.rstrip("/") + path for path in exposed]),
                    "remediation": [
                        "Restrict public access to sensitive directories.",
                        "Use proper web server configuration and access controls."
                    ],
                    "impact": "Can lead to unauthorized access, data leaks or full server compromise."
                })
            elif not silent:
                print("[+] No exposed sensitive paths detected.")

            # --- SSL Check ---
            expired, expiry = self.check_expired_ssl()
            if expired is True:
                if not silent:
                    print('\033[91m' + "[!] SSL certificate expired: {expiry}" + '\033[0m')
                results.append({
                    "name": "Expired SSL Certificate",
                    "severity": "Medium",
                    "description": "The SSL certificate for this host has expired.",
                    "poc": f"{self.url} - Expires: {expiry}",
                    "remediation": ["Renew the SSL/TLS certificate to maintain secure communication."],
                    "impact": "Users may receive security warnings. Potential for MITM attacks."
                })
            elif expired is False and not silent:
                print(f"\033[92m[+] SSL certificate is valid. Expires on: {expiry}\033[0m")
            elif not silent:
                print(f"[~] Could not verify SSL: {expiry}")

        except KeyboardInterrupt:
            if not silent:
                print("\n[!] Misconfiguration scan interrupted by user.")
        except Exception as e:
            if not silent:
                print(f"[!] Failed to perform checks: {e}")

        return results
