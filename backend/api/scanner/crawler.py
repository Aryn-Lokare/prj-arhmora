import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger(__name__)

class Crawler:
    def __init__(self, base_url, max_pages=10):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited_urls = set()
        self.urls_to_visit = [base_url]
        self.max_pages = max_pages
        self.discovered_forms = []
        self.discovered_params = set()

    def is_same_domain(self, url):
        return urlparse(url).netloc == self.domain

    def crawl(self):
        pages_crawled = 0
        while self.urls_to_visit and pages_crawled < self.max_pages:
            url = self.urls_to_visit.pop(0)
            if url in self.visited_urls:
                continue

            try:
                logger.info(f"Crawling: {url}")
                response = requests.get(url, timeout=5, verify=False) # verify=False for local/dev sites
                self.visited_urls.add(url)
                pages_crawled += 1

                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Discover links
                    for link in soup.find_all('a', href=True):
                        full_url = urljoin(url, link['href'])
                        # Strip query params for discovery logic but keep for forms
                        clean_url = full_url.split('?')[0].split('#')[0]
                        if self.is_same_domain(clean_url) and clean_url not in self.visited_urls:
                            self.urls_to_visit.append(full_url)

                    # Discover forms
                    for form in soup.find_all('body'): # Scanning body for forms
                        for f in form.find_all('form'):
                            form_data = {
                                'url': url,
                                'action': f.get('action'),
                                'method': f.get('method', 'get').lower(),
                                'inputs': []
                            }
                            for input_tag in f.find_all(['input', 'textarea', 'select']):
                                name = input_tag.get('name')
                                if name:
                                    form_data['inputs'].append({
                                        'name': name,
                                        'type': input_tag.get('type', 'text')
                                    })
                                    self.discovered_params.add(name)
                            self.discovered_forms.append(form_data)

                    # Discover query params
                    parsed_url = urlparse(url)
                    if parsed_url.query:
                        params = parsed_url.query.split('&')
                        for p in params:
                            if '=' in p:
                                self.discovered_params.add(p.split('=')[0])

            except Exception as e:
                logger.error(f"Error crawling {url}: {e}")

        return {
            'visited_urls': list(self.visited_urls),
            'forms': self.discovered_forms,
            'params': list(self.discovered_params)
        }
