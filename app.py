from flask import Flask, render_template, request, Response
import json
from scanner import AttackSurfaceScanner
from risk_engine import RiskEngine
from report import Reporter

app = Flask(__name__)

# --- ROUTE 1: THE MAIN DASHBOARD ---
@app.route('/', methods=['GET', 'POST'])
def index():
    domain = None
    subs = []
    risk_data = None

    if request.method == 'POST':
        domain = request.form.get('domain')
        if domain:
            # 1. Initialize and run the scanner
            scanner = AttackSurfaceScanner(domain)
            raw_results = scanner.run_all()
            subs = scanner.subdomains
            
            # 2. Process results through the Risk Engine
            engine = RiskEngine(raw_results)
            risk_data = engine.evaluate()
            
            # 3. Render the page with the results
            return render_template('index.html', domain=domain, subs=subs, risk_data=risk_data)
        
    # Default view for GET requests (initial load)
    return render_template('index.html', domain=None)


# --- ROUTE 2: THE JSON REPORT DOWNLOAD ---
@app.route('/download', methods=['POST'])
def download():
    domain = request.form.get('domain')
    if not domain:
        return "Domain required", 400

    # Re-run or fetch the data (in a real app, you'd cache this)
    scanner = AttackSurfaceScanner(domain)
    raw_results = scanner.run_all()
    engine = RiskEngine(raw_results)
    risk_data = engine.evaluate()
    
    # Use the Reporter module to format the JSON string
    json_data = Reporter.get_json_string(domain, raw_results, risk_data)
    
    # Return the file as a downloadable attachment
    return Response(
        json_data,
        mimetype="application/json",
        headers={"Content-disposition": f"attachment; filename={domain}_security_report.json"}
    )

if __name__ == '__main__':
    # Run the Flask server
    app.run(debug=True, port=5000)