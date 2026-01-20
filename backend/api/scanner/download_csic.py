import os
import requests
import time

BASE_URLS = [
    "https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/main/OriginalDataSets/CSIC%202010/",
    "https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master/OriginalDataSets/CSIC%202010/",
    "https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/main/",
    "https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master/"
]
OUTPUT_DIR = "data/csic2010"

FILES = [
    "normalTrafficTraining.txt",
    "normalTrafficTest.txt",
    "anomalousTrafficTest.txt"
]

def download_file(filename):
    output_path = os.path.join(OUTPUT_DIR, filename)
    
    for base_url in BASE_URLS:
        url = base_url + filename
        print(f"Trying {url}...")
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                with open(output_path, 'wb') as f:
                    f.write(response.content)
                print(f"  [SUCCESS] Saved to {output_path} ({len(response.content)} bytes)")
                return True
        except Exception as e:
            pass
            
    print(f"  [FAILED] Could not find {filename} in any known path")
    return False

if __name__ == "__main__":
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        
    success_count = 0
    for f in FILES:
        if download_file(f):
            success_count += 1
        time.sleep(1) # Be nice to GitHub
        
    if success_count == len(FILES):
        print("\nAll files downloaded successfully.")
    else:
        print(f"\nDownloaded {success_count}/{len(FILES)} files. Some downloads failed.")
        print("Please manually download missing files to data/csic2010/")
