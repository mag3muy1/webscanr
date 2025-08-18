import re
import requests
from bs4 import BeautifulSoup
from webtech import WebTech
from webtech.utils import ConnectionException
from urllib.parse import urlparse

class TechnologyScanner:
    FRONTEND_TECH_REGEX = {
        "jQuery": [
            r"jquery[-.](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"jquery[-.](\d+\.\d+)(?:\.min)?\.js",
            r"jquery(?:\.min)?\.js\?ver=(\d+\.\d+\.\d+)",
            r"jquery(?:\.min)?\.js\?v=(\d+\.\d+\.\d+)",
            r"/jquery/(\d+\.\d+\.\d+)/jquery(?:\.min)?\.js",
            r"cdn\.jsdelivr\.net/npm/jquery@(\d+\.\d+\.\d+)",
            r"code\.jquery\.com/jquery-(\d+\.\d+\.\d+)",
        ],
        "Bootstrap": [
            r"bootstrap[-.](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)",
            r"bootstrap/(\d+\.\d+\.\d+)/",
            r"bootstrap(?:\.min)?\.(?:js|css)\?ver=(\d+\.\d+\.\d+)",
            r"cdn\.jsdelivr\.net/npm/bootstrap@(\d+\.\d+\.\d+)",
        ],
        # ... other frontend tech regex patterns ...
    }

    BACKEND_CATEGORIES = [
        'Apache', 'Nginx', 'IIS', 'Node.js', 'Express', 'Django',
        'Flask', 'Ruby on Rails', 'Laravel', 'WordPress', 'PHP',
        'ASP.NET', 'ASP.NET Core', 'Java', 'Spring', '.NET', 
        'Microsoft SQL Server', 'MySQL', 'PostgreSQL'
    ]

    @staticmethod
    def _extract_version_from_url(url, patterns):
        """Helper method to extract version from URL using multiple patterns"""
        for pattern in patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                for group in match.groups():
                    if group:  # Return the first non-empty group
                        return group
        return None

    @staticmethod
    def _get_page_content(url):
        """Helper method to fetch page content with proper headers"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            }
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            print(f"[!] Error fetching {url}: {e}")
            return None

    @staticmethod
    def extract_frontend_technologies(url):
        """Detect frontend technologies from page content"""
        try:
            content = TechnologyScanner._get_page_content(url)
            if not content:
                return []

            soup = BeautifulSoup(content, "html.parser")
            detected = {}

            # Check script src and link href attributes
            for tag in soup.find_all(["script", "link"]):
                src = tag.get("src") or tag.get("href")
                if not src:
                    continue

                # Handle relative URLs
                if src.startswith("//"):
                    src = f"https:{src}"
                elif src.startswith("/"):
                    parsed_url = urlparse(url)
                    src = f"{parsed_url.scheme}://{parsed_url.netloc}{src}"

                for tech, patterns in TechnologyScanner.FRONTEND_TECH_REGEX.items():
                    version = TechnologyScanner._extract_version_from_url(src, patterns)
                    if version and tech not in detected:
                        detected[tech] = version

            # Check inline scripts for framework indicators
            for script in soup.find_all("script", string=True):
                script_content = script.string
                if not script_content:
                    continue

                # Detect frameworks in inline scripts
                if "jQuery" in script_content or "$." in script_content:
                    if "jQuery" not in detected:
                        detected["jQuery"] = "Unknown (inline detection)"
                if "ReactDOM" in script_content or "createElement" in script_content:
                    if "React" not in detected:
                        detected["React"] = "Unknown (inline detection)"

            return [{"name": k, "version": v} for k, v in detected.items()]

        except Exception as e:
            print(f"[!] Error extracting frontend tech: {e}")
            return []

    @staticmethod
    def detect_backend_technologies(url):
        try:
            wt = WebTech(options={'json': True})
            result = wt.start_from_url(url)

            seen = {}
            for tech in result.get("tech", []):
                name = tech.get("name")
                version = tech.get("version")
                
                # Special handling for .NET Framework versions
                if name and "ASP.NET" in name and version:
                    # Convert version format (4.0.30319 → 4.0)
                    version_parts = version.split('.')
                    if len(version_parts) >= 2:
                        version = f"{version_parts[0]}.{version_parts[1]}"
                
                if name and (name not in seen or (version and not seen[name])):
                    seen[name] = version

            return [{"name": name, "version": version} for name, version in seen.items()]
        except Exception as e:
            print(f"[!] Error in backend detection: {e}")
            return []

    @staticmethod
    def get_website_technologies(url):
        """Get both frontend and backend technologies for a given URL"""
        try:
            backend_techs = TechnologyScanner.detect_backend_technologies(url)
            frontend_techs = TechnologyScanner.extract_frontend_technologies(url)
            
            # Ensure all technologies have name and version fields
            for tech_list in [backend_techs, frontend_techs]:
                for tech in tech_list:
                    tech.setdefault('name', 'Unknown')
                    tech.setdefault('version', 'Unknown')

            # Categorize technologies
            categorized = {
                'frontend': [],
                'backend': [],
                'other': []
            }

            for tech in frontend_techs:
                categorized['frontend'].append(tech)

            for tech in backend_techs:
                name = tech["name"]
                is_backend = any(
                    backend.lower() in name.lower() 
                    for backend in TechnologyScanner.BACKEND_CATEGORIES
                )
                
                if is_backend:
                    categorized['backend'].append(tech)
                else:
                    categorized['other'].append(tech)

            return categorized

        except Exception as e:
            print(f"[!] Error fingerprinting {url}: {e}")
            return {'frontend': [], 'backend': [], 'other': []}

    @staticmethod
    def print_technologies(tech_info, url):
        """Print the detected technologies in a formatted way"""
        print(f"\n========== Technology Fingerprinting: {url} ==========")
        
        if not tech_info:
            print("[-] No technologies detected.")
            return

        def format_version(tech):
            if isinstance(tech.get('version'), dict):
                return tech['version']['full']
            return tech.get('version', 'Unknown')

        if tech_info['frontend']:
            print("\nFrontend Technologies")
            for tech in sorted(tech_info['frontend'], key=lambda x: x['name']):
                print(f"  • {tech['name']}: {format_version(tech)}")

        if tech_info['backend']:
            print("\nBackend Technologies")
            for tech in sorted(tech_info['backend'], key=lambda x: x['name']):
                version_display = format_version(tech)
                if "ASP.NET" in tech['name'] and isinstance(tech.get('version'), dict):
                    version_display += f" (major.minor: {tech['version']['major_minor']})"
                print(f"  • {tech['name']}: {version_display}")

        if tech_info['other']:
            print("\nOther Technologies")
            for tech in sorted(tech_info['other'], key=lambda x: x['name']):
                print(f"  • {tech['name']}: {format_version(tech)}")