class RiskEngine:
    # A small sample of known vulnerable versions for demonstration
    VULNERABILITY_DB = {
        "Apache/2.4.49": "CVE-2021-41773: Path Traversal and Remote Code Execution",
        "nginx/1.18.0": "CVE-2021-23017: Potential Remote Code Execution in DNS resolver",
        "Microsoft-IIS/7.5": "End-of-Life: This version is no longer supported and is highly vulnerable.",
        "PHP/5.4.16": "CVE-2019-11043: Remote Code Execution via PHP-FPM"
    }

    def __init__(self, scan_results):
        self.results = scan_results
        self.findings = []
        self.overall_score = 0
        self.tech_info = self.results.get("tech_stack", {})

    def evaluate(self):
        # --- 1. NEW: CVE Version Matching ---
        server_version = self.tech_info.get("server", "")
        for version, cve_desc in self.VULNERABILITY_DB.items():
            if version in server_version:
                self.findings.append({
                    "severity": "CRITICAL", 
                    "issue": f"Known Exploit Found: {cve_desc}"
                })
                self.overall_score += 15 # Huge jump in risk

        # --- 2. Existing Information Disclosure Check ---
        if self.tech_info.get("info_leak") and self.overall_score < 15:
            self.findings.append({
                "severity": "Medium", 
                "issue": f"Information Disclosure: Server version leaked ({server_version})"
            })
            self.overall_score += 4

        # ... (Keep your existing HTTPS and Port checks here) ...

        return self.calculate_final_risk()

    def calculate_final_risk(self):
        # Ensure we pass the tech_info back to the UI
        risk_summary = {
            "risk_level": self._get_label(),
            "risk_score": self.overall_score,
            "findings": self.findings,
            "tech_info": self.tech_info # This is crucial for index.html
        }
        return risk_summary

    def _get_label(self):
        if self.overall_score >= 20: return "CRITICAL"
        if self.overall_score >= 10: return "HIGH"
        if self.overall_score >= 5: return "MEDIUM"
        return "LOW"