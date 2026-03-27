class RiskEngine:
    def __init__(self, scan_results):
        self.results = scan_results
        self.findings = []
        self.overall_score = 0

    def evaluate(self):
        # 1. Critical Checks (Score: 10)
        for vuln in self.results.get("mock_vulnerabilities", []):
            if vuln["type"] == "Reflected XSS":
                self.findings.append({"severity": "Critical", "issue": f"Reflected XSS simulated at {vuln['endpoint']}"})
                self.overall_score += 10

        # 2. High Checks (Score: 7)
        if not self.results.get("https_enabled"):
            self.findings.append({"severity": "High", "issue": "HTTPS is missing or not enforced."})
            self.overall_score += 7

        # 3. Medium Checks (Score: 4)
        ports = self.results.get("ports", {})
        if ports.get(22) == "open":
            self.findings.append({"severity": "Medium", "issue": "SSH port 22 is open to the public."})
            self.overall_score += 4
        if ports.get(21) == "open":
            self.findings.append({"severity": "Medium", "issue": "FTP port 21 is open to the public."})
            self.overall_score += 4

        # 4. Low Checks (Score: 1)
        headers = self.results.get("headers", {})
        for header, status in headers.items():
            if status == "Missing":
                self.findings.append({"severity": "Low", "issue": f"Missing security header: {header}"})
                self.overall_score += 1

        return self.calculate_final_risk()

    def calculate_final_risk(self):
        if self.overall_score >= 10:
            level = "CRITICAL"
        elif self.overall_score >= 7:
            level = "HIGH"
        elif self.overall_score >= 4:
            level = "MEDIUM"
        elif self.overall_score > 0:
            level = "LOW"
        else:
            level = "SECURE"
            
        return {
            "risk_level": level,
            "risk_score": self.overall_score,
            "findings": self.findings
        }