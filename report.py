import json

class Reporter:
    @staticmethod
    def print_cli(domain, subdomains, risk_data):
        print("\n" + "="*50)
        print(f" ATTACK SURFACE REPORT: {domain}")
        print("="*50)
        print(f"\n[+] Discovered Subdomains: {', '.join(subdomains) if subdomains else 'None found'}")
        
        print(f"\n[+] OVERALL RISK LEVEL: {risk_data['risk_level']} (Score: {risk_data['risk_score']})")
        print("\n[+] Findings:")
        for finding in risk_data['findings']:
            print(f"    - [{finding['severity']}] {finding['issue']}")
        print("\n" + "="*50)

    @staticmethod
    def generate_json(domain, scan_results, risk_data):
        report = {
            "target": domain,
            "raw_scan_data": scan_results,
            "risk_analysis": risk_data
        }
        filename = f"{domain}_report.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"[*] JSON report saved to {filename}")

# Add this to report.py
    @staticmethod
    def get_json_string(domain, scan_results, risk_data):
        report = {
            "target": domain,
            "raw_scan_data": scan_results,
            "risk_analysis": risk_data
        }
        return json.dumps(report, indent=4)