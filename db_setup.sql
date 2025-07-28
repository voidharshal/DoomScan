CREATE TABLE IF NOT EXISTS scan_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_url TEXT NOT NULL,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    findings JSON,
    CONSTRAINT chk_findings CHECK (JSON_VALID(findings))
);