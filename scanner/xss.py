import requests

class XSSScanner:
    def __init__(self, session):
        # We inherit the session from the crawler to maintain state/login
        self.session = session
        # We use a unique, identifiable payload to prevent false positives
        self.payload = "<script>alert('XSS_TEST_PAYLOAD')</script>"
        self.vulnerabilities = []

    def scan_forms(self, forms):
        """Iterates through extracted forms and injects the XSS payload."""
        print("[*] Starting XSS Scanning on extracted forms...")
        for form in forms:
            action = form.get('action')
            method = form.get('method')
            inputs = form.get('inputs')

            # Prepare the malicious data payload
            form_data = {}
            for input_field in inputs:
                input_name = input_field.get('name')
                input_type = input_field.get('type')
                
                # Inject payload into text-based fields
                if input_name and input_type in ['text', 'search', 'email', 'password']:
                    form_data[input_name] = self.payload
                elif input_name:
                    form_data[input_name] = "dummy_data"

            self._submit_and_check(action, method, form_data)

    def _submit_and_check(self, action, method, data):
        """Submits the payload and checks for exact reflection in the response."""
        try:
            # Handle POST vs GET methods dynamically
            if method == 'post':
                response = self.session.post(action, data=data)
            else:
                response = self.session.get(action, params=data)
            
            # The core detection logic: checking for EXACT reflection
            if self.payload in response.text:
                print(f"[!] HIGH SEVERITY: Reflected XSS found at {action}")
                self.vulnerabilities.append({
                    'type': 'XSS',
                    'severity': 'High',
                    'url': action,
                    'payload': self.payload
                })
        except requests.exceptions.RequestException as e:
            print(f"[-] Error testing XSS on {action}: {e}")

    def get_results(self):
        return self.vulnerabilities