import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class Crawler:
    def __init__(self, target_url):
        self.target_url = target_url
        # We use a Session object to keep track of cookies/logins across requests
        self.session = requests.Session() 
        self.forms_found = []

    def crawl(self):
        """Fetches the target URL and parses the HTML to find injection points."""
        print(f"[*] Starting crawl on: {self.target_url}")
        try:
            response = self.session.get(self.target_url)
            # BeautifulSoup parses the raw HTML so we can search it
            soup = BeautifulSoup(response.text, 'html.parser') 
            self._extract_forms(soup, self.target_url)
        except requests.exceptions.RequestException as e:
            print(f"[!] Error crawling {self.target_url}: {e}")

    def _extract_forms(self, soup, url):
        """Finds all HTML forms and their input fields."""
        for form in soup.find_all('form'):
            form_details = {}
            # Get the form's target URL (action) and HTTP method (GET or POST)
            action = form.attrs.get('action', '')
            form_details['action'] = urljoin(url, action)
            form_details['method'] = form.attrs.get('method', 'get').lower()
            
            # Extract all input fields within the form
            inputs = []
            for input_tag in form.find_all('input'):
                input_name = input_tag.attrs.get('name')
                input_type = input_tag.attrs.get('type', 'text')
                if input_name:
                    inputs.append({'name': input_name, 'type': input_type})
            
            form_details['inputs'] = inputs
            self.forms_found.append(form_details)
            print(f"[+] Found form on {url} with {len(inputs)} inputs.")

    def get_forms(self):
        return self.forms_found