import subprocess
import requests
import socket
import urllib3

# Suppress insecure request warnings for educational testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AttackSurfaceScanner:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = []
        self.scan_results = {
            "ports": {},
            "headers": {},
            "https_enabled": False,
            "mock_vulnerabilities": []
        }

    def discover_subdomains(self):
        """Basic mock subdomain enumeration via DNS resolution."""
        common_subs = ['www', 'mail', 'dev', 'test', 'api']
        discovered = []
        for sub in common_subs:
            target = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(target)
                discovered.append(target)
            except socket.gaierror:
                pass
        self.subdomains = discovered
        return self.subdomains

    def scan_ports(self):
        """Uses Nmap via subprocess to scan common ports."""
        ports = "21,22,80,443"
        try:
            # -sT for TCP connect scan (no root required), -T4 for speed
            result = subprocess.run(
                ['nmap', '-p', ports, '-sT', '-T4', self.domain],
                capture_output=True, text=True, timeout=30
            )
            output = result.stdout
            
            # Simple parsing of nmap output
            for port in [21, 22, 80, 443]:
                if f"{port}/tcp open" in output:
                    self.scan_results["ports"][port] = "open"
                else:
                    self.scan_results["ports"][port] = "closed/filtered"
        except FileNotFoundError:
            self.scan_results["ports"]["error"] = "Nmap not installed or not in PATH."
        except subprocess.TimeoutExpired:
            self.scan_results["ports"]["error"] = "Nmap scan timed out."

    def check_web_security(self):
        """Checks for HTTPS and security headers."""
        url = f"http://{self.domain}"
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            # Check if it ultimately redirected to HTTPS
            self.scan_results["https_enabled"] = response.url.startswith("https")
            
            headers = response.headers
            self.scan_results["headers"] = {
                "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
                "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing"),
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing")
            }
        except requests.RequestException:
            self.scan_results["error"] = "Could not connect to web server."

    def mock_xss_test(self):
        """
        MOCK CHECK: Simulates finding an XSS vulnerability.
        Active payload injection is omitted for safety compliance.
        """
        self.scan_results["mock_vulnerabilities"].append({
            "type": "Reflected XSS",
            "endpoint": "/search?q=",
            "status": "Simulated Detection"
        })

    def run_all(self):
        self.discover_subdomains()
        self.scan_ports()
        self.check_web_security()
        self.mock_xss_test()
        return self.scan_results