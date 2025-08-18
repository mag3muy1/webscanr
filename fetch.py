import requests
from bs4 import BeautifulSoup
import re
import json
from datetime import datetime
import time

# Predefined latest versions as fallback
LATEST_VERSIONS = {
    "jQuery": "3.7.1",
    "Bootstrap": "5.3.3",
    "Microsoft ASP.NET": "4.8.1",
    "React": "18.2.0",
    "Moment.js": "2.30.1",
    "TensorFlow.js": "4.22.0",
    "Electron": "28.1.0",
    "PHP": "8.3.8",
    "Nginx": "1.25.5",
    "Django": "5.0.4"
}

def fetch_jquery_version():
    try:
        response = requests.get("https://jquery.com/download/", timeout=10)
        response.raise_for_status()
        match = re.search(r"jQuery Core (\d+\.\d+\.\d+)", response.text)
        return match.group(1) if match else LATEST_VERSIONS["jQuery"]
    except:
        return LATEST_VERSIONS["jQuery"]

def fetch_bootstrap_version():
    try:
        response = requests.get("https://getbootstrap.com/docs/versions/", timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        version_div = soup.find('div', class_='version')
        return version_div.text.strip() if version_div else LATEST_VERSIONS["Bootstrap"]
    except:
        return LATEST_VERSIONS["Bootstrap"]

def fetch_aspnet_version():
    try:
        response = requests.get("https://dotnet.microsoft.com/download/dotnet-framework", timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        version_div = soup.find('div', class_='version')
        full_version = version_div.text.strip() if version_div else LATEST_VERSIONS["Microsoft ASP.NET"]
        return '.'.join(full_version.split('.')[:2])  # Return major.minor format
    except:
        return LATEST_VERSIONS["Microsoft ASP.NET"]

def fetch_react_version():
    try:
        response = requests.get("https://reactjs.org/", timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        # Look for version in the page - this might need adjustment based on actual page structure
        version_tag = soup.find('span', class_='version')
        return version_tag.text.strip() if version_tag else LATEST_VERSIONS["React"]
    except:
        return LATEST_VERSIONS["React"]

def fetch_momentjs_version():
    try:
        response = requests.get("https://momentjs.com/", timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        # Look for version in the page - this might need adjustment
        version_tag = soup.find('div', class_='version-number')
        return version_tag.text.strip() if version_tag else LATEST_VERSIONS["Moment.js"]
    except:
        return LATEST_VERSIONS["Moment.js"]

def fetch_tensorflowjs_version():
    try:
        response = requests.get("https://www.tensorflow.org/js", timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        # Look for version in the page - this might need adjustment
        version_tag = soup.find('span', class_='version')
        return version_tag.text.strip() if version_tag else LATEST_VERSIONS["TensorFlow.js"]
    except:
        return LATEST_VERSIONS["TensorFlow.js"]

def fetch_electron_version():
    try:
        response = requests.get("https://www.electronjs.org/releases/stable", timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        # Look for latest stable version
        version_tag = soup.find('h1')
        if version_tag:
            match = re.search(r'v(\d+\.\d+\.\d+)', version_tag.text)
            return match.group(1) if match else LATEST_VERSIONS["Electron"]
        return LATEST_VERSIONS["Electron"]
    except:
        return LATEST_VERSIONS["Electron"]

def fetch_php_version():
    try:
        response = requests.get("https://www.php.net/downloads", timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        # Look for current stable version
        version_tag = soup.find('p', class_='version')
        if version_tag:
            match = re.search(r'PHP (\d+\.\d+\.\d+)', version_tag.text)
            return match.group(1) if match else LATEST_VERSIONS["PHP"]
        return LATEST_VERSIONS["PHP"]
    except:
        return LATEST_VERSIONS["PHP"]

def fetch_nginx_version():
    try:
        response = requests.get("https://nginx.org/en/download.html", timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        # Look for stable version
        version_tag = soup.find('h4')
        if version_tag:
            match = re.search(r'nginx-(\d+\.\d+\.\d+)', version_tag.text)
            return match.group(1) if match else LATEST_VERSIONS["Nginx"]
        return LATEST_VERSIONS["Nginx"]
    except:
        return LATEST_VERSIONS["Nginx"]

def fetch_django_version():
    try:
        response = requests.get("https://www.djangoproject.com/download/", timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        # Look for latest version
        version_tag = soup.find('div', class_='version')
        return version_tag.text.strip() if version_tag else LATEST_VERSIONS["Django"]
    except:
        return LATEST_VERSIONS["Django"]

def fetch_all_latest_versions():
    """Fetch latest versions with fallback to predefined values"""
    return {
        "jQuery": fetch_jquery_version(),
        "Bootstrap": fetch_bootstrap_version(),
        "Microsoft ASP.NET": fetch_aspnet_version(),
        "React": fetch_react_version(),
        "Moment.js": fetch_momentjs_version(),
        "TensorFlow.js": fetch_tensorflowjs_version(),
        "Electron": fetch_electron_version(),
        "PHP": fetch_php_version(),
        "Nginx": fetch_nginx_version(),
        "Django": fetch_django_version()
    }


if __name__ == "__main__":
    versions = fetch_all_latest_versions()
    print("Latest versions fetched and saved.")