# scanner/crawler.py

import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from collections import deque


class WebCrawler:
    def __init__(self, base_url, max_pages=30):
        self.base_url = base_url.rstrip("/")
        self.max_pages = max_pages
        self.visited = set()
        self.found_links = []

    def is_same_domain(self, url):
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    def crawl(self):
        queue = deque([self.base_url])
        print(f"\n========== Crawling: {self.base_url} ==========")

        while queue and len(self.visited) < self.max_pages:
            url = queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)
            self.found_links.append(url)

            try:
                response = requests.get(url, timeout=5, verify=False)
                soup = BeautifulSoup(response.text, "html.parser")
                for tag in soup.find_all("a", href=True):
                    href = urljoin(url, tag["href"])
                    if self.is_same_domain(href) and href not in self.visited:
                        queue.append(href)
            except requests.RequestException:
                continue

        self.print_results()
        return self.found_links

    def print_results(self):
        if not self.found_links:
            print("[-] No links found.")
        else:
            for i, link in enumerate(self.found_links, 1):
                print(f"[{i}] {link}")
