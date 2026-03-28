from flask import Flask, render_template, request
import sys
import os

# This ensures Python can find your 'scanner' folder from inside the 'dashboard' folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner.crawler import Crawler
from scanner.xss import XSSScanner
from scanner.sqli import SQLiScanner
from scanner.redirect import RedirectScanner
from scanner.reporter import Reporter

app = Flask(__name__)

@app.route('/')
def index():
    # Loads the default homepage
    return render_template('index.html', results=None)

@app.route('/scan', methods=['POST'])
def scan():
    # This runs when the user clicks the "Scan" button
    target_url = request.form.get('url')
    if not target_url:
        return render_template('index.html', error="Please provide a valid URL.", results=None)

    print(f"[*] Dashboard initiated scan on: {target_url}")

    # Step 1: Initialize Crawler
    crawler = Crawler(target_url)
    crawler.crawl()
    forms = crawler.get_forms()
    session = crawler.session # Grab the session so we stay logged in

    vulnerabilities = []

    # Step 2: Run all attack modules if forms were found
    if forms:
        # XSS Scan
        xss_scanner = XSSScanner(session)
        xss_scanner.scan_forms(forms)
        vulnerabilities.extend(xss_scanner.get_results())

        # SQLi Scan
        sqli_scanner = SQLiScanner(session)
        sqli_scanner.scan_forms(forms)
        vulnerabilities.extend(sqli_scanner.get_results())

        # Open Redirect Scan
        redirect_scanner = RedirectScanner(session)
        redirect_scanner.scan_forms(forms)
        vulnerabilities.extend(redirect_scanner.get_results())

    # Step 3: Generate the JSON and HTML reports locally
    reporter = Reporter(target_url, vulnerabilities)
    reporter.generate_json()
    reporter.generate_html()

    # Step 4: Pass the data back to the web browser to display the color-coded table
    return render_template('index.html', target=target_url, results=vulnerabilities)

if __name__ == '__main__':
    # Runs the web server
    app.run(debug=True)