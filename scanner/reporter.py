import json
import os
from datetime import datetime

class Reporter:
    def __init__(self, target_url, vulnerabilities):
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities
        self.scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Ensure a reports directory exists
        if not os.path.exists('reports'):
            os.makedirs('reports')

    def generate_json(self):
        """Exports the vulnerability findings as a structured JSON file."""
        report_data = {
            "target": self.target_url,
            "scan_time": self.scan_time,
            "total_vulnerabilities": len(self.vulnerabilities),
            "findings": self.vulnerabilities
        }
        
        filename = f"reports/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=4)
        print(f"[+] JSON report generated: {filename}")
        return filename

    def generate_html(self):
        """Generates a human-readable HTML report of the findings."""
        filename = f"reports/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        html_content = f"""
        <html>
        <head>
            <title>Vulnerability Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f9; }}
                h1 {{ color: #333; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background-color: #fff; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #2c3e50; color: white; }}
                .Critical {{ color: white; background-color: #e74c3c; font-weight: bold; padding: 4px; border-radius: 4px; }}
                .High {{ color: white; background-color: #e67e22; font-weight: bold; padding: 4px; border-radius: 4px; }}
                .Medium {{ color: black; background-color: #f1c40f; font-weight: bold; padding: 4px; border-radius: 4px; }}
            </style>
        </head>
        <body>
            <h1>Vulnerability Scan Report</h1>
            <p><strong>Target:</strong> {self.target_url}</p>
            <p><strong>Scan Time:</strong> {self.scan_time}</p>
            <p><strong>Total Findings:</strong> {len(self.vulnerabilities)}</p>
            
            <table>
                <tr>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>URL / Parameter</th>
                    <th>Payload Used</th>
                </tr>
        """
        
        for vuln in self.vulnerabilities:
            html_content += f"""
                <tr>
                    <td>{vuln['type']}</td>
                    <td><span class="{vuln['severity']}">{vuln['severity']}</span></td>
                    <td>{vuln['url']}</td>
                    <td><code>{vuln['payload']}</code></td>
                </tr>
            """
            
        html_content += """
            </table>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
        print(f"[+] HTML report generated: {filename}")
        return filename