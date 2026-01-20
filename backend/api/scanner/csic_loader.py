import os
import re
import logging
from typing import List, Dict, Tuple

logger = logging.getLogger(__name__)

class CSICDataLoader:
    """
    Loader for CSIC 2010 HTTP Dataset.
    Parses raw HTTP request logs into a structured format for feature extraction.
    """
    
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        
    def load_data(self) -> Tuple[List[Dict], List[int]]:
        """
        Load training and test data.
        
        Returns:
            Tuple of (all_requests, all_labels)
            where label 0 = normal, 1 = anomalous
        """
        normal_train_path = os.path.join(self.data_dir, "normalTrafficTraining.txt")
        normal_test_path = os.path.join(self.data_dir, "normalTrafficTest.txt")
        anomalous_test_path = os.path.join(self.data_dir, "anomalousTrafficTest.txt")
        
        requests = []
        labels = []
        
        # Load Normal Training
        if os.path.exists(normal_train_path):
            print(f"Loading {normal_train_path}...")
            norm_train = self._parse_file(normal_train_path)
            requests.extend(norm_train)
            labels.extend([0] * len(norm_train))
        else:
            print(f"Warning: {normal_train_path} not found.")

        # Load Normal Test
        if os.path.exists(normal_test_path):
            print(f"Loading {normal_test_path}...")
            norm_test = self._parse_file(normal_test_path)
            requests.extend(norm_test)
            labels.extend([0] * len(norm_test))
        else:
            print(f"Warning: {normal_test_path} not found.")
            
        # Load Anomalous Test
        if os.path.exists(anomalous_test_path):
            print(f"Loading {anomalous_test_path}...")
            anom_test = self._parse_file(anomalous_test_path)
            requests.extend(anom_test)
            labels.extend([1] * len(anom_test))
        else:
            print(f"Warning: {anomalous_test_path} not found.")
            
        return requests, labels

    def _parse_file(self, filepath: str) -> List[Dict]:
        """
        Parse a CSIC 2010 raw text file.
        Requests are separated by blank lines? Actually CSIC format is tricky.
        Usually it implies parsing HTTP headers.
        
        We'll look for lines starting with GET/POST/PUT etc.
        """
        parsed_requests = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Split by double newline which often separates requests in these logs
            # If that doesn't work, we iterate line by line expecting a Method line start
            
            blocks = content.split('\n\n')
            
            for block in blocks:
                if not block.strip():
                    continue
                    
                lines = block.strip().split('\n')
                first_line = lines[0].strip()
                
                # Regex to match HTTP request line: METHOD URL HTTP/VERSION
                match = re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d\.\d$', first_line)
                
                if match:
                    method = match.group(1)
                    url = match.group(2)
                    
                    # Basic extraction, we mostly care about the URL for now
                    # Header parsing could be added if needed for metadata features
                    headers = {}
                    for line in lines[1:]:
                        if ':' in line:
                            parts = line.split(':', 1)
                            headers[parts[0].strip()] = parts[1].strip()
                            
                    parsed_requests.append({
                        'method': method,
                        'url': url,
                        'headers': headers,
                        'raw': block
                    })
                    
        except Exception as e:
            logger.error(f"Error parsing {filepath}: {e}")
            
        return parsed_requests

if __name__ == "__main__":
    # Test loader
    loader = CSICDataLoader("data/csic2010")
    reqs, lbls = loader.load_data()
    print(f"Loaded {len(reqs)} requests.")
