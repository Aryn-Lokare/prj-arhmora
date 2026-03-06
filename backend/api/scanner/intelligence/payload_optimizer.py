from . import learning_store
from . import ml_models

def prioritize_payloads(url, vuln_type, default_payloads):
    """
    Sort payloads based on historical success and ML scoring.
    """
    history = learning_store.get_history(url, vuln_type)
    remaining = [p for p in default_payloads if p not in history]
    return history + remaining

def get_mutation_tips(framework: str, vuln_type: str) -> list:
    """
    Returns framework-specific payloads to "level up" the scan.
    """
    tips = {
        "WordPress": {
            "Local File Inclusion (LFI)": ["wp-config.php", "wp-content/debug.log"],
            "Server-Side Request Forgery (SSRF)": ["http://localhost/wp-admin/admin-ajax.php"],
        },
        "Django": {
            "Information Disclosure": ["settings.py", ".env", "manage.py"],
            "SQL Injection": ["' OR 1=1 --", "') OR ('a'='a"],
        },
        "Laravel": {
            "Local File Inclusion (LFI)": [".env", "storage/logs/laravel.log"],
            "Remote Code Execution (RCE)": ["{{config('app.key')}}"],
        },
        "Express.js": {
            "Local File Inclusion (LFI)": ["package.json", "node_modules/"],
        }
    }
    
    return tips.get(framework, {}).get(vuln_type, [])
