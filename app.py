import os
import json
from flask import send_file, Flask, render_template, request, redirect, url_for
from itsdangerous import URLSafeSerializer
from dotenv import load_dotenv
import mysql.connector
import psycopg2
from urllib.parse import urlparse
from psycopg2.extras import DictCursor
from scanner.main_scanner import run_scan
from scanner.report_generator import generate_report

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a03348b72957f8c99310b3207aae856b')
serializer = URLSafeSerializer(app.config['SECRET_KEY'])

PDF_FOLDER = 'temp_reports'
if not os.path.exists(PDF_FOLDER):
    os.makedirs(PDF_FOLDER)

def get_scan_history():
    """Helper function to fetch scan history for the sidebar."""
    scans = []
    try:
        db_url = os.getenv('DATABASE_URL')
        result = urlparse(db_url)
        # Use a 'with' statement for automatic connection closing
        with psycopg2.connect(
            dbname=result.path[1:],
            user=result.username,
            password=result.password,
            host=result.hostname
        ) as db:
            with db.cursor(cursor_factory=DictCursor) as cursor: # Use DictCursor
                cursor.execute("SELECT id, target_url, scan_date FROM scan_results ORDER BY scan_date DESC")
                scans = cursor.fetchall()
    except (psycopg2.Error, TypeError) as err: # Catch psycopg2 errors
        print(f"Database Error: {err}")
    return scans

@app.route('/')
def index():
    """Renders the main page with the new scan form."""
    scans = get_scan_history()
    return render_template('index.html', scans=scans)

@app.route('/about')
def about():
    """Renders the about page."""
    scans = get_scan_history()
    return render_template('about.html', scans=scans)

@app.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    """Displays the results of a specific past scan."""
    scans = get_scan_history() # For the sidebar
    scan_details = {}
    try:
        db = mysql.connector.connect(host=os.getenv('DB_HOST'), user=os.getenv('DB_USER'), password=os.getenv('DB_PASSWORD'), database=os.getenv('DB_NAME'))
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT target_url, findings FROM scan_results WHERE id = %s", (scan_id,))
        result = cursor.fetchone()
        if result:
            scan_details['url'] = result['target_url']
            scan_details['findings'] = json.loads(result['findings'])
            scan_details['findings_str'] = serializer.dumps(scan_details['findings'])
        cursor.close()
        db.close()
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
    
    return render_template('results.html', scans=scans, **scan_details)

# --- Your existing scan and download routes remain below ---
# Note: You can now delete the old @app.route('/history') as it's no longer needed.

@app.route('/scan', methods=['POST'])
def scan_passive():
    url_to_scan = request.form.get('url_to_scan')
    findings = run_scan(url_to_scan, perform_active_scan=False)
    # Save results and get the new ID
    new_scan_id = save_scan_to_db(url_to_scan, findings)
    # Redirect to the results page for the new scan
    return redirect(url_for('view_scan', scan_id=new_scan_id))

@app.route('/scan_active', methods=['POST'])
def scan_active():
    url_to_scan = request.form.get('url_to_scan')
    findings = run_scan(url_to_scan, perform_active_scan=True)
    # Save results and get the new ID
    new_scan_id = save_scan_to_db(url_to_scan, findings)
    # Redirect to the results page for the new scan
    return redirect(url_for('view_scan', scan_id=new_scan_id))

@app.route('/download_report', methods=['POST'])
def download_report():
    url = request.form.get('url')
    findings_str = request.form.get('findings_str')
    findings = serializer.loads(findings_str)
    file_path = os.path.join(PDF_FOLDER, 'report.pdf')
    generate_report(url, findings, file_path)
    return send_file(file_path, as_attachment=True)

@app.route('/glossary')
def glossary():
    """Renders the glossary page."""
    scans = get_scan_history()
    return render_template('glossary.html', scans=scans)

# Don't forget to add the save_scan_to_db function if you removed it
def save_scan_to_db(target_url, findings):
    """Saves the scan results and returns the new scan's ID."""
    last_id = None
    try:
        db_url = os.getenv('DATABASE_URL')
        result = urlparse(db_url)
        with psycopg2.connect(
            dbname=result.path[1:],
            user=result.username,
            password=result.password,
            host=result.hostname
        ) as db:
            with db.cursor() as cursor:
                findings_json = json.dumps(findings)
                # Use RETURNING id to get the new ID in PostgreSQL
                sql = "INSERT INTO scan_results (target_url, findings) VALUES (%s, %s) RETURNING id"
                val = (target_url, findings_json)
                cursor.execute(sql, val)
                last_id = cursor.fetchone()[0]
                db.commit() # Commit the transaction
    except (psycopg2.Error, TypeError) as err: # Catch psycopg2 errors
        print(f"Database Error: {err}")
    return last_id

if __name__ == '__main__':
    app.run(debug=True)