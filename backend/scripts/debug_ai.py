from api.scanner.ai_model import AIInference
import os

engine = AIInference(model_dir='api/scanner')
print(f"Loaded: {engine.loaded}")

urls = [
    "http://example.com/login",
    "http://google.com",
    "https://github.com/trending",
    "https://stackoverflow.com/questions/12345",
    "http://example.com/search?q=<script>alert(1)</script>",
    "http://example.com/user?id=1' OR 1=1",
    "http://test.com/exec?cmd=cat /etc/passwd"
]

for url in urls:
    prob = engine.predict(url)
    severity = engine.calculate_severity(prob)
    print(f"URL: {url}\n  Prob: {prob:.4f} | Severity: {severity}")
