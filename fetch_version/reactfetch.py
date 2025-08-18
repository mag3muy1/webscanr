import requests
from bs4 import BeautifulSoup
import re

def fetch_react_version():
    """
    Fetches the latest React version from the official website.
    :return: Latest version as a string (e.g., "19.0").
    """
    # URL for React versions
    url = "https://react.dev/versions"

    try:
        # Fetch the website content
        response = requests.get(url)
        response.raise_for_status()

        # Parse the HTML content
        soup = BeautifulSoup(response.text, "html.parser")

        # Find the <h2> tag with the id "latest-version"
        version_container = soup.find("h2", id="latest-version")

        if version_container:
            # Extract the text content of the <h2> tag
            version_text = version_container.text.strip()

            # Use regex to extract the version number (e.g., "19.0")
            version_number = re.search(r"\d+\.\d+", version_text)
            if version_number:
                return version_number.group(0)
            else:
                print("[!] Could not extract version number from the text.")
                return None
        else:
            print("[!] Could not find the version container.")
            return None
    except requests.RequestException as e:
        print(f"[!] Error fetching React version: {e}")
        return None
