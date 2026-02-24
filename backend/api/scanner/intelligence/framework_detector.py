from . import ml_models

def detect_framework(headers: dict, body: str) -> str:
    """
    Identify web framework using signatures and ML fallback.
    """
    # 1. Rule-based detection
    body_lower = body.lower()
    
    # Django
    if "csrftoken" in headers.get("Set-Cookie", "") or "csrfmiddlewaretoken" in body:
        return "Django"
        
    # Laravel
    if "laravel_session" in headers.get("Set-Cookie", "") or "laravel" in body_lower:
        return "Laravel"
        
    # Express / Node.js
    if "express" in headers.get("X-Powered-By", "").lower():
        return "Express.js"
        
    # WordPress
    if "wp-content" in body or "wp-includes" in body:
        return "WordPress"

    # 2. ML Fallback
    ml_result = ml_models.predict_framework({"headers": headers, "body": body})
    if ml_result:
        return ml_result

    return "Unknown"
