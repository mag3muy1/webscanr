import requests
from packaging import version
import time
from urllib.parse import unquote

class NVDChecker:
    def __init__(self, tech_info):
        self.tech_info = tech_info
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {'User-Agent': 'WebScanr/1.0'}
        self.rate_limit_delay = 1.5  # Be kind to NVD API

    def get_flattened_tech_list(self):
        flat_list = []
        for category in ['frontend', 'backend', 'other']:
            if isinstance(self.tech_info.get(category), list):
                flat_list.extend(self.tech_info[category])
        return flat_list

    def is_vulnerable(self, cpe_match, tech_version):
        if not tech_version or tech_version.lower() in ['unknown', 'none', '']:
            return False
        
        try:
            end_version = cpe_match.get('versionEndIncluding') or cpe_match.get('versionEndExcluding')
            if end_version:
                return version.parse(tech_version) <= version.parse(end_version)
        except:
            return False
        return False

    def get_severity(self, metrics):
        if not metrics:
            return "UNKNOWN"
        for metric in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if metric in metrics and metrics[metric]:
                try:
                    return metrics[metric][0]['cvssData'].get('baseSeverity', 'UNKNOWN')
                except (KeyError, TypeError):
                    continue
        return "UNKNOWN"

    def get_score(self, metrics):
        for metric in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if metric in metrics and metrics[metric]:
                try:
                    return metrics[metric][0]['cvssData'].get('baseScore', 'N/A')
                except (KeyError, TypeError):
                    continue
        return 'N/A'

    def query_cves(self, product, version_str):
        # Clean product name and version
        product = product.split('/')[0].strip()
        version_str = str(version_str).split('-')[0].strip() if version_str else None

        if not version_str or version_str.lower() in ['unknown', 'none', '']:
            return []

        params = {
            "keywordSearch": product,
            "resultsPerPage": 50
        }

        try:
            time.sleep(self.rate_limit_delay)
            response = requests.get(self.base_url, params=params, headers=self.headers, timeout=15)
            response.raise_for_status()
            
            relevant_cves = []
            for vuln in response.json().get("vulnerabilities", []):
                cve_data = vuln.get('cve', {})
                configurations = cve_data.get('configurations', [])
                affects_our_version = False

                for config in configurations:
                    for node in config.get('nodes', []):
                        for cpe_match in node.get('cpeMatch', []):
                            criteria = unquote(cpe_match.get('criteria', '')).lower()
                            if f":{product.lower()}:" in criteria:
                                if self.is_vulnerable(cpe_match, version_str):
                                    affects_our_version = True
                                    break

                if affects_our_version:
                    relevant_cves.append(vuln)

            return relevant_cves

        except Exception as e:
            print(f"[!] Error querying {product}: {e}")
            return []

    def check(self, verbose=False):
        print("\n========== NVD Vulnerability Check ==========")
        print("Note: Only checking technologies with known versions\n")
        
        results = []
        tech_list = self.get_flattened_tech_list()
        if not tech_list:
            print("[-] No technology information available")
            return results

        for tech in tech_list:
            if not isinstance(tech, dict):
                continue

            name = tech.get("name", "").strip()
            ver = tech.get("version", "")
            
            if not name:
                continue

            if not ver or str(ver).lower() in ['unknown', 'none', '']:
                if verbose:
                    print(f"\nChecking {name} - SKIPPED (version unknown)")
                continue

            cves = self.query_cves(name, ver)

            if cves:
                print(f"\033[91m[!] Found {len(cves)} relevant vulnerabilities:\033[0m")
                for cve in sorted(
                    cves,
                    key=lambda x: (
                        self.get_severity(x.get('cve', {}).get('metrics', {})),
                        x.get('cve', {}).get('published', '')
                    ),
                    reverse=True
                )[:5]:  # Show top 5
                    cve_data = cve.get('cve', {})
                    cve_id = cve_data.get('id', 'Unknown')
                    desc = next(
                        (d['value'] for d in cve_data.get('descriptions', []) if d['lang'] == 'en'),
                        'No description available'
                    )
                    severity = self.get_severity(cve_data.get('metrics', {}))
                    score = self.get_score(cve_data.get('metrics', {}))

                    print(f"  - {cve_id} ({severity}, CVSS: {score}): {desc[:120]}...")

                    results.append({
                        "name": f"{name} - {cve_id}",
                        "severity": severity,
                        "score": score,
                        "description": desc,
                        "poc": f"Version: {ver} is affected by {cve_id}",
                        "remediation": ["Upgrade to the latest patched version."],
                        "impact": f"{cve_id} affects {name} version {ver}",
                        "reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    })
            else:
                if verbose:
                    print(f"\nChecking {name} {ver}...")
                    print('\033[92m' + "[+] No relevant vulnerabilities found" '\033[0m')

        return results