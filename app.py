from flask import Flask, render_template, request, jsonify
from scanner import AttackSurfaceScanner
from risk_engine import RiskEngine

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form.get('domain')
        if not domain:
            return "Domain is required", 400
            
        # Run Scanner
        scanner = AttackSurfaceScanner(domain)
        raw_results = scanner.run_all()
        
        # Run Risk Engine
        engine = RiskEngine(raw_results)
        risk_data = engine.evaluate()
        
        return render_template('index.html', domain=domain, subs=scanner.subdomains, risk_data=risk_data)
        
    return render_template('index.html', domain=None)

if __name__ == '__main__':
    app.run(debug=True)