import requests
from bs4 import BeautifulSoup
import re

def fetch_bootstrap_version():
    """
    Fetches the latest Bootstrap version from the official website.
    :return: Latest version as a string (e.g., "5.3").
    """
    # URL for Bootstrap versions
    url = "https://getbootstrap.com/docs/versions/"

    try:
        # Fetch the website content
        response = requests.get(url)
        response.raise_for_status()

        # Parse the HTML content
        soup = BeautifulSoup(response.text, "html.parser")

        # Find the container that holds the version links
        version_container = soup.find("div", class_="col-md-6 col-lg-4 col-xl mb-4")

        if version_container:
            # Find all <a> tags within the container
            version_links = version_container.find_all("a", class_="list-group-item")

            # Iterate through the links to find the one with the "Latest" badge
            for link in version_links:
                # Check if the link contains a <span> with the text "Latest"
                latest_badge = link.find("span", class_="badge", string="Latest")
                if latest_badge:
                    # Extract the version number (e.g., "5.3" from "5.3 Latest")
                    version_text = link.text.strip()
                    version_number = re.search(r"\d+\.\d+", version_text)
                    if version_number:
                        return version_number.group(0)
            print("[!] Could not find the latest Bootstrap version.")
            return None
        else:
            print("[!] Could not find the version container.")
            return None
    except requests.RequestException as e:
        print(f"[!] Error fetching Bootstrap version: {e}")
        return None