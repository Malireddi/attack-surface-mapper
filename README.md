# Web Vulnerability Scanner

## Project Overview
[cite_start]A Python-based security tool that automatically scans web applications for common vulnerabilities[cite: 3]. [cite_start]It combines a CLI scanner engine with a Flask web dashboard, allowing users to input a target URL and receive a severity-scored vulnerability report - mimicking the kind of automated scanning workflows used by real security teams[cite: 4].

## Tech Stack
* [cite_start]**Core Logic:** Python [cite: 6]
* [cite_start]**HTTP Traffic & Payloads:** Requests [cite: 7]
* [cite_start]**HTML Parsing & Extraction:** BeautifulSoup [cite: 8]
* [cite_start]**Frontend Web Dashboard:** Flask [cite: 9]
* [cite_start]**Report Output Formats:** JSON / HTML [cite: 10, 11]

## Key Features
* [cite_start]Automated crawling of forms and URL parameters[cite: 31].
* [cite_start]Multi-vector scanning engine targeting Cross-Site Scripting (XSS), SQL Injection (SQLi), and Open Redirects[cite: 31].
* [cite_start]Dynamic routing for both POST and GET form methods[cite: 39, 44].
* [cite_start]Intelligent payload reflection logic to minimize XSS false positives[cite: 38, 43].
* [cite_start]Severity-scored output (Critical / High / Medium)[cite: 32].
* [cite_start]Flask web dashboard for non-CLI users[cite: 34].

## Installation

1. Clone this repository to your local machine.
2. Ensure you have Python 3 installed.
3. Install the necessary dependencies:
   ```bash
   pip install -r requirements.txt