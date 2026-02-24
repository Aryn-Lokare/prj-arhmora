from . import learning_store
from . import ml_models

def prioritize_payloads(url, vuln_type, default_payloads):
    """
    Sort payloads based on historical success and ML scoring.
    1. Historical successful payloads first.
    2. ML scored payloads next.
    3. Remaining defaults.
    """
    # 1. Fetch historical successes from this target
    history = learning_store.get_history(url, vuln_type)
    
    # 2. Score remaining payloads using ML (or rule-based fallback)
    remaining = [p for p in default_payloads if p not in history]
    
    # Simple scoring logic: history > ML score > default order
    # For now, we return history + sorted remaining
    
    return history + remaining
