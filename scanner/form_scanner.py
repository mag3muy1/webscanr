import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FormScanner:
    @staticmethod
    def get_all_forms(url):
        response = requests.get(url, verify=False)  # Force ignore certificate
        soup = bs(response.content, "html.parser")
        return soup.find_all("form")

    @staticmethod
    def get_form_details(form):
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    @staticmethod
    def submit_form(form_details, url, value, timeout = 10):
        target_url = urljoin(url, form_details["action"])
        inputs = form_details["inputs"]
        data = {}
        for input in inputs:
            if input["type"] in ["text", "search"]:
                input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value

        if form_details["method"] == "post":
            return requests.post(target_url, data=data, verify=False, timeout=timeout)
        else:
            return requests.get(target_url, params=data, verify=False, timeout=timeout)
