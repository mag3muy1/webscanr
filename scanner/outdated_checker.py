from packaging import version
from fetch import fetch_all_latest_versions


class OutdatedComponentChecker:
    def __init__(self, detected_tech):
        """
        :param detected_tech: List of dictionaries, e.g.
               [{'name': 'jQuery', 'version': '3.5.1'}, {'name': 'PHP', 'version': '7.2.34'}]
        """
        self.detected_tech = detected_tech
        self.latest_versions = fetch_all_latest_versions()

    def version_is_outdated(self, current_version, latest_version):
        try:
            # Handle .NET version comparison
            if isinstance(current_version, str) and (".NET" in current_version or "ASP.NET" in current_version):
                current_version = '.'.join(current_version.split('.')[:2])
            
            return version.parse(current_version) < version.parse(latest_version)
        except:
            return False

    def check_outdated(self, verbose=False):
        print("\n========== Outdated Components Check ==========")
        report_entries = []
        
        for tech in self.detected_tech:
            if not isinstance(tech, dict):
                continue
                
            name = tech.get("name", "").strip()
            version = str(tech.get("version", "")).strip()
            
            if not name:
                continue
                
            # Special handling for ASP.NET version format
            if "ASP.NET" in name and version:
                # Convert version format (4.0.30319 → 4.0.0 for comparison)
                version_parts = version.split('.')
                if len(version_parts) >= 3:
                    compare_version = f"{version_parts[0]}.{version_parts[1]}.0"
                else:
                    compare_version = version
            else:
                compare_version = version
                
            if not compare_version or compare_version.lower() in ['unknown', 'none', '']:
                if verbose:
                    print(f"[~] {name} - version unknown")
                continue
                
            latest_version = self.latest_versions.get(name)
            if not latest_version:
                if verbose:
                    print(f"[~] No version data for {name}")
                continue
                
            if self.version_is_outdated(compare_version, latest_version):
                print(f"[!] {name} is outdated! Detected: \033[91m{version}\033[0m, Latest: \033[92m{latest_version}\033[0m")
                report_entries.append({
                    "name": name,
                    "severity": "Medium",
                    "description": f"{name} {version} is outdated. Latest is {latest_version}.",
                    "poc": f"Version {version} in use.",
                    "remediation": [f"Upgrade to {latest_version}."],
                    "impact": f"Running outdated {name} could lead to security vulnerabilities."
                })
            elif verbose:
                print(f"[+] {name} is up-to-date: \033[92m{version}\033[0m")

        return report_entries