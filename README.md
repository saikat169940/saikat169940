import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

class SAIKAT:
    def __init__(self, url):
        self.url = url
        self.visited_links = set()

    def find_forms(self):
        """Extract all forms from the web page"""
        response = requests.get(self.url)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")

    def form_details(self, form):
        """Extract useful information from the form"""
        details = {}
        action = form.attrs.get("action").lower()
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

    def is_vulnerable_to_xss(self, form_details):
        """Basic test to check for XSS vulnerability"""
        xss_payload = "<script>alert('XSS')</script>"
        url = urljoin(self.url, form_details["action"])
        inputs = form_details["inputs"]
        data = {}
        for input in inputs:
            if input["type"] == "text":
                data[input["name"]] = xss_payload
        if form_details["method"] == "post":
            res = requests.post(url, data=data)
        else:
            res = requests.get(url, params=data)
        return xss_payload in res.content.decode()

    def scan_sql_injection(self):
        """Basic test to check for SQL injection vulnerability"""
        sql_payload = "' OR '1'='1"
        vulnerable = False
        response = requests.get(self.url)
        soup = BeautifulSoup(response.content, "html.parser")
        for link in soup.find_all("a"):
            href = link.get("href")
            if href and urlparse(href).netloc == "":
                full_url = urljoin(self.url, href)
                self.visited_links.add(full_url)
                if sql_payload in full_url:
                    vulnerable = True
        return vulnerable

    def scan(self):
        forms = self.find_forms()
        for form in forms:
            details = self.form_details(form)
            if self.is_vulnerable_to_xss(details):
                print(f"XSS vulnerability detected on {self.url}")
                break
        if self.scan_sql_injection():
            print(f"SQL Injection vulnerability detected on {self.url}")

if __name__ == "__main__":
    url = input("Enter URL to scan: ")
    saikat = SAIKAT(url)
    saikat.scan()
