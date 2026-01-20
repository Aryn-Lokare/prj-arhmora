"""
Behavioral Time-Window Analysis Module.

This module provides sliding window behavioral analysis for:
- Request frequency tracking per source
- Pattern repetition detection
- Burst detection
- Distributed attack detection
"""

import time
import hashlib
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class RequestRecord:
    """Record of a single request for behavioral tracking."""
    url: str
    timestamp: float
    url_hash: str


class BehavioralAnalyzer:
    """
    Sliding window behavioral analysis for distributed attack detection.
    
    This analyzer tracks requests per source IP within a configurable time window
    to detect:
    - Abnormal request frequency (too many requests per minute)
    - URL repetition patterns (same endpoint hit repeatedly)
    - Burst patterns (rapid consecutive requests)
    """
    
    # Default configuration
    DEFAULT_WINDOW_SIZE = 300  # 5 minutes in seconds
    DEFAULT_FREQUENCY_THRESHOLD = 60  # requests per minute
    DEFAULT_REPETITION_THRESHOLD = 0.7  # 70% same endpoint
    DEFAULT_BURST_THRESHOLD = 10  # requests within 5 seconds
    DEFAULT_BURST_WINDOW = 5  # seconds
    
    def __init__(self, 
                 window_size: int = None,
                 frequency_threshold: int = None,
                 repetition_threshold: float = None,
                 burst_threshold: int = None,
                 burst_window: int = None):
        """
        Initialize the behavioral analyzer.
        
        Args:
            window_size: Sliding window size in seconds (default: 300)
            frequency_threshold: Max requests per minute before anomaly (default: 60)
            repetition_threshold: Max ratio of same-endpoint requests (default: 0.7)
            burst_threshold: Max requests within burst window (default: 10)
            burst_window: Burst detection window in seconds (default: 5)
        """
        self.window_size = window_size or self.DEFAULT_WINDOW_SIZE
        self.frequency_threshold = frequency_threshold or self.DEFAULT_FREQUENCY_THRESHOLD
        self.repetition_threshold = repetition_threshold or self.DEFAULT_REPETITION_THRESHOLD
        self.burst_threshold = burst_threshold or self.DEFAULT_BURST_THRESHOLD
        self.burst_window = burst_window or self.DEFAULT_BURST_WINDOW
        
        # In-memory request cache: source_ip -> list of RequestRecords
        self._request_cache: Dict[str, List[RequestRecord]] = defaultdict(list)
        self._lock = Lock()
    
    def _hash_url(self, url: str) -> str:
        """Create a hash of the URL for pattern detection."""
        return hashlib.md5(url.encode()).hexdigest()[:16]
    
    def _clean_old_requests(self, source_ip: str, current_time: float) -> None:
        """Remove requests outside the sliding window."""
        cutoff = current_time - self.window_size
        self._request_cache[source_ip] = [
            r for r in self._request_cache[source_ip]
            if r.timestamp > cutoff
        ]
    
    def record_request(self, source_ip: str, url: str, 
                       timestamp: Optional[float] = None) -> None:
        """
        Record a request in the sliding window.
        
        Args:
            source_ip: Source IP address of the request
            url: Requested URL
            timestamp: Request timestamp (defaults to current time)
        """
        if timestamp is None:
            timestamp = time.time()
        
        record = RequestRecord(
            url=url,
            timestamp=timestamp,
            url_hash=self._hash_url(url)
        )
        
        with self._lock:
            self._clean_old_requests(source_ip, timestamp)
            self._request_cache[source_ip].append(record)
    
    def get_behavioral_metrics(self, source_ip: str) -> Dict[str, float]:
        """
        Get behavioral metrics for a source IP.
        
        Metrics returned:
        - request_count: Total requests in window
        - requests_per_minute: Average request rate
        - repetition_rate: Ratio of most common URL to total
        - burst_count: Requests in the most recent burst window
        - unique_urls: Number of unique URLs requested
        
        Args:
            source_ip: Source IP to analyze
            
        Returns:
            Dictionary of behavioral metrics
        """
        current_time = time.time()
        
        with self._lock:
            self._clean_old_requests(source_ip, current_time)
            requests = self._request_cache.get(source_ip, [])
        
        if not requests:
            return {
                'request_count': 0,
                'requests_per_minute': 0.0,
                'repetition_rate': 0.0,
                'burst_count': 0,
                'unique_urls': 0,
            }
        
        request_count = len(requests)
        
        # Calculate requests per minute
        if request_count > 1:
            time_span = requests[-1].timestamp - requests[0].timestamp
            if time_span > 0:
                requests_per_minute = (request_count / time_span) * 60
            else:
                requests_per_minute = float(request_count)
        else:
            requests_per_minute = float(request_count)
        
        # Calculate repetition rate (most common URL ratio)
        url_counts = defaultdict(int)
        for r in requests:
            url_counts[r.url_hash] += 1
        max_count = max(url_counts.values()) if url_counts else 0
        repetition_rate = max_count / request_count if request_count > 0 else 0.0
        
        # Calculate burst count (requests in last burst_window seconds)
        burst_cutoff = current_time - self.burst_window
        burst_count = sum(1 for r in requests if r.timestamp > burst_cutoff)
        
        # Unique URLs
        unique_urls = len(url_counts)
        
        return {
            'request_count': request_count,
            'requests_per_minute': requests_per_minute,
            'repetition_rate': repetition_rate,
            'burst_count': burst_count,
            'unique_urls': unique_urls,
        }
    
    def detect_anomalies(self, source_ip: str) -> Dict[str, any]:
        """
        Detect behavioral anomalies for a source IP.
        
        Anomalies detected:
        - frequency_anomaly: Too many requests per minute
        - repetition_anomaly: Same endpoint hit too frequently
        - burst_anomaly: Too many rapid consecutive requests
        
        Args:
            source_ip: Source IP to analyze
            
        Returns:
            Dictionary with anomaly flags and details
        """
        metrics = self.get_behavioral_metrics(source_ip)
        
        frequency_anomaly = metrics['requests_per_minute'] > self.frequency_threshold
        repetition_anomaly = metrics['repetition_rate'] > self.repetition_threshold
        burst_anomaly = metrics['burst_count'] > self.burst_threshold
        
        # Calculate anomaly score (0-1)
        anomaly_score = 0.0
        anomaly_reasons = []
        
        if frequency_anomaly:
            freq_excess = metrics['requests_per_minute'] / self.frequency_threshold
            anomaly_score += min(0.4, 0.4 * (freq_excess - 1))
            anomaly_reasons.append(f"High frequency: {metrics['requests_per_minute']:.1f} req/min")
        
        if repetition_anomaly:
            rep_excess = metrics['repetition_rate'] / self.repetition_threshold
            anomaly_score += min(0.3, 0.3 * (rep_excess - 1))
            anomaly_reasons.append(f"High repetition: {metrics['repetition_rate']:.1%}")
        
        if burst_anomaly:
            burst_excess = metrics['burst_count'] / self.burst_threshold
            anomaly_score += min(0.3, 0.3 * (burst_excess - 1))
            anomaly_reasons.append(f"Burst detected: {metrics['burst_count']} req/{self.burst_window}s")
        
        return {
            'has_anomaly': frequency_anomaly or repetition_anomaly or burst_anomaly,
            'frequency_anomaly': frequency_anomaly,
            'repetition_anomaly': repetition_anomaly,
            'burst_anomaly': burst_anomaly,
            'anomaly_score': min(1.0, anomaly_score),
            'anomaly_reasons': anomaly_reasons,
            'metrics': metrics,
        }
    
    def get_behavioral_risk_score(self, source_ip: str) -> int:
        """
        Get a risk score (0-100) based on behavioral analysis.
        
        Args:
            source_ip: Source IP to analyze
            
        Returns:
            Risk score from 0 (normal) to 100 (highly anomalous)
        """
        anomalies = self.detect_anomalies(source_ip)
        return int(anomalies['anomaly_score'] * 100)
    
    def clear_source(self, source_ip: str) -> None:
        """Clear all recorded requests for a source IP."""
        with self._lock:
            if source_ip in self._request_cache:
                del self._request_cache[source_ip]
    
    def clear_all(self) -> None:
        """Clear all recorded requests."""
        with self._lock:
            self._request_cache.clear()
    
    def get_active_sources(self) -> List[str]:
        """Get list of source IPs with recorded requests."""
        current_time = time.time()
        active = []
        
        with self._lock:
            for source_ip in list(self._request_cache.keys()):
                self._clean_old_requests(source_ip, current_time)
                if self._request_cache[source_ip]:
                    active.append(source_ip)
        
        return active
