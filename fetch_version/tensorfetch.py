import requests
from bs4 import BeautifulSoup
import re

def fetch_tensor_version():
    """
    Fetches the latest TensorFlow.js version from the GitHub releases page.
    :return: Latest version as a string (e.g., "tfjs-v4.0.0").
    """
    # URL for TensorFlow.js releases
    url = "https://github.com/tensorflow/tfjs/releases"

    try:
        # Fetch the website content
        response = requests.get(url)
        response.raise_for_status()

        # Parse the HTML content
        soup = BeautifulSoup(response.text, "html.parser")

        # Find the first release title (latest release)
        release_title = soup.find("a", attrs={"href": re.compile(r"/releases/tag/")})

        if release_title:
            # Extract the text content of the release title
            version_text = release_title.text.strip()

            # Use regex to extract the version number (e.g., "tfjs-v4.0.0")
            version_number = re.search(r"\d+\.\d+\.\d+", version_text)
            if version_number:
                return version_number.group(0)
            else:
                print("[!] Could not extract version number from the text.")
                return None
        else:
            print("[!] Could not find the release title.")
            return None
    except requests.RequestException as e:
        print(f"[!] Error fetching TensorFlow.js version: {e}")
        return None
