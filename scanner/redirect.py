import requests

class RedirectScanner:
    def __init__(self, session):
        self.session = session
        # The external domain we try to redirect the user to
        self.payload = "http://evil.com"
        # Common URL parameters developers use for redirecting traffic
        self.target_params = ['next', 'url', 'redirect', 'return', 'go']
        self.vulnerabilities = []

    def scan_forms(self, forms):
        """Tests extracted GET forms for open redirect vulnerabilities."""
        print("[*] Starting Open Redirect Scanning...")
        for form in forms:
            action = form.get('action')
            method = form.get('method')
            inputs = form.get('inputs')

            # Open redirects usually happen in GET requests
            if method == 'get':
                for input_field in inputs:
                    input_name = input_field.get('name')
                    # Only test fields that look like they handle URLs
                    if input_name in self.target_params:
                        self._test_redirect(action, input_name)

    def _test_redirect(self, url, param_name):
        """Injects external URL and checks the Location header."""
        test_data = {param_name: self.payload}
        try:
            # CRITICAL: allow_redirects=False stops Python from automatically following the redirect
            response = self.session.get(url, params=test_data, allow_redirects=False)
            
            # Check if the server responds with a redirect status code (301, 302, etc.)
            if response.status_code in [301, 302, 303, 307, 308]:
                # Grab the 'Location' header to see where the server is trying to send us
                location = response.headers.get('Location', '')
                
                # If the server is sending us to evil.com, it's vulnerable
                if location == self.payload:
                    print(f"[!] MEDIUM SEVERITY: Open Redirect found at {url}?{param_name}={self.payload}")
                    self.vulnerabilities.append({
                        'type': 'Open Redirect',
                        'severity': 'Medium',
                        'url': f"{url}?{param_name}={self.payload}",
                        'payload': self.payload
                    })
        except requests.exceptions.RequestException as e:
            print(f"[-] Error testing Open Redirect on {url}: {e}")

    def get_results(self):
        return self.vulnerabilities