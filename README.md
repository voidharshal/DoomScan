# 🕵️‍♂️ DoomScan

**DoomScan** is a lightweight web vulnerability scanner built using **Python** and **Flask**.  
It allows users to perform quick reconnaissance on websites, checking for open ports, insecure headers, misconfigurations, and other basic vulnerabilities — all through a clean, browser-based interface.

---

## ⚙️ Features
- Scan any target URL for potential vulnerabilities  
- Detect open ports and misconfigured headers  
- Generate and store detailed scan reports  
- Simple, intuitive web dashboard  
- Built with modular code for easy extension

---

## 🧩 Tech Stack
- **Backend:** Python (Flask)  
- **Frontend:** HTML, CSS  
- **Database:** SQLite (via `db_setup.sql`)  

---

## 💻 Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/voidharshal/DoomScan.git
   cd DoomScan

2. **Create a virtual environment**
    ```bash
    python -m venv venv
    source venv/bin/activate    #for mac/linux
    venv\Scripts\activate       #for windows

3. **Install dependencies**
    ```bash
    pip install -r requirements.txt

4. **Set up the database**
    ```bash
    python db_setup.sql

5. **Run the flask app**
    ```bash
    python app.py

6. **Access the app**
    open the browser and go to:
    http://127.0.0.1:5000/

## Project structure
    ```bash
    DoomScan/
    │  app.py
    │  requirements.txt
    │  db_setup.sql
    │  .env
    │
    ├─ scanner/           # Core vulnerability scanning logic
    ├─ static/            # CSS and other static files
    ├─ templates/         # HTML templates
    └─ temp_reports/      # Generated scan reports

