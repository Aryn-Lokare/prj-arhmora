import sys
import os

# Add backend to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.scanner.intelligence.exploit_verifier import classify_exploit

def print_result(scenario, payload, response, delay):
    print(f"\n[SCENARIO]: {scenario}")
    print(f"Payload: {payload}")
    result = classify_exploit(payload, response, delay)
    print(f"Detected Type: {result['type']}")
    print(f"Confidence: {result['confidence']}%")
    print(f"Evidence: {result['evidence']}")
    print(f"Risk Score: {result['risk_score']}")

# Test Case 1: Pure SQLi Time-Based
print_result(
    "SQLi Time-Based (True Positive)",
    "' AND SLEEP(5)--",
    {"body": "<html>...</html>", "status_code": 200},
    True
)

# Test Case 2: Pure RCE Time-Based (but no OS output)
print_result(
    "RCE Time-Based (Suspicious - No OS markers in payload)",
    "sleep 5",
    {"body": "<html>...</html>", "status_code": 200},
    True
)

# Test Case 3: RCE with Command Separator and Delay
print_result(
    "RCE Time-Based (Confirmed via Markers)",
    "; sleep 5",
    {"body": "<html>...</html>", "status_code": 200},
    True
)

# Test Case 4: RCE with OS Output (Highest Confidence)
print_result(
    "RCE Output-Based (True Positive)",
    "; id",
    {"body": "uid=0(root) gid=0(root) groups=0(root)", "status_code": 200},
    False
)

# Test Case 5: SQLi SLEEP() triggering RCE logic (False Positive Reduction)
print_result(
    "SQLi SLEEP in RCE check (False Positive Avoidance)",
    "' AND SLEEP(5)--",
    {"body": "<html>...</html>", "status_code": 200},
    True
)

# Test Case 6: Delay detected but no context markers (Suspicious)
print_result(
    "Generic Delay (Suspicious)",
    "some_param=value",
    {"body": "<html>...</html>", "status_code": 200},
    True
)
