import os
import json
from flask import send_file, Flask, render_template, request
from itsdangerous import URLSafeSerializer
from dotenv import load_dotenv
import mysql.connector
from scanner.main_scanner import run_scan
from scanner.report_generator import generate_report

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a03348b72957f8c99310b3207aae856b')

serializer = URLSafeSerializer(app.config['SECRET_KEY'])

PDF_FOLDER = 'temp_reports'
if not os.path.exists(PDF_FOLDER):
    os.makedirs(PDF_FOLDER)

def save_scan_to_db(target_url, findings):
    try:
        db = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME')
        )
        cursor = db.cursor()
        findings_json = json.dumps(findings)
        sql = "INSERT INTO scan_results (target_url, findings) VALUES (%s, %s)"
        val = (target_url, findings_json)
        cursor.execute(sql, val)
        db.commit()
        cursor.close()
        db.close()
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_passive():
    url_to_scan = request.form.get('url_to_scan')
    findings = run_scan(url_to_scan, perform_active_scan=False)
    save_scan_to_db(url_to_scan, findings)
    findings_str = serializer.dumps(findings)
    return render_template('results.html', url=url_to_scan, findings=findings, findings_str=findings_str)

@app.route('/scan_active', methods=['POST'])
def scan_active():
    url_to_scan = request.form.get('url_to_scan')
    findings = run_scan(url_to_scan, perform_active_scan=True)
    save_scan_to_db(url_to_scan, findings)
    findings_str = serializer.dumps(findings)
    return render_template('results.html', url=url_to_scan, findings=findings, findings_str=findings_str)

@app.route('/download_report', methods=['POST'])
def download_report():
    url = request.form.get('url')
    findings_str = request.form.get('findings_str')
    findings = serializer.loads(findings_str)
    file_path = os.path.join(PDF_FOLDER, 'report.pdf')
    generate_report(url, findings, file_path)
    
    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)