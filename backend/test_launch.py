from playwright.sync_api import sync_playwright
import sys

try:
    print("Attempting to launch Playwright Chromium...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        print("SUCCESS: Browser launched.")
        browser.close()
except Exception as e:
    print(f"FAILED: {str(e)}")
    sys.exit(1)
