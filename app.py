from flask import Flask, render_template, request
from scanner.main_scanner import run_scan
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url_to_scan = request.form.get('url_to_scan')
    findings = run_scan(url_to_scan)
    return render_template('results.html', url=url_to_scan, findings=findings)

if __name__ == '__main__':
    app.run(debug=True)