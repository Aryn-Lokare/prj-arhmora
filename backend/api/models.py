# backend/api/models.py

import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from django.conf import settings


class EmailVerificationToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verification_tokens')
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Verification token for {self.user.email}"

    def is_expired(self):
        expiry_hours = getattr(settings, 'EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS', 24)
        expiry_time = self.created_at + timedelta(hours=expiry_hours)
        return timezone.now() > expiry_time

    def is_valid(self):
        return not self.is_used and not self.is_expired()


class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Password reset token for {self.user.email}"

    def is_expired(self):
        expiry_hours = getattr(settings, 'PASSWORD_RESET_TOKEN_EXPIRY_HOURS', 1)
        expiry_time = self.created_at + timedelta(hours=expiry_hours)
        return timezone.now() > expiry_time

    def is_valid(self):
        return not self.is_used and not self.is_expired()


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    is_email_verified = models.BooleanField(default=False)
    phone = models.CharField(max_length=15, blank=True, null=True)
    avatar = models.URLField(max_length=500, blank=True, null=True)  # Changed to URLField for Google avatar
    bio = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email}'s profile"



class SocialAccount(models.Model):
    """Store social login account information"""
    
    PROVIDER_CHOICES = [
        ('google', 'Google'),
        ('github', 'GitHub'),
        ('facebook', 'Facebook'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='social_accounts')
    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES)
    provider_id = models.CharField(max_length=255)  # Google's unique user ID
    access_token = models.TextField(blank=True, null=True)
    refresh_token = models.TextField(blank=True, null=True)
    extra_data = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('provider', 'provider_id')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.email} - {self.provider}"



class ScanHistory(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Completed', 'Completed'),
        ('Failed', 'Failed'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scans')
    target_url = models.URLField()
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    task_id = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"Scan for {self.target_url} by {self.user.username}"


class ScanFinding(models.Model):
    SEVERITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
    ]

    scan = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, related_name='findings')
    v_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    affected_url = models.URLField()
    evidence = models.TextField()
    remediation = models.TextField()
    remediation_simple = models.TextField(blank=True, default='')
    remediation_technical = models.TextField(blank=True, default='')
    
    # AI-Generated Explanations (non-technical and technical)
    explanation_simple = models.TextField(blank=True, default='')  # For non-technical users
    explanation_technical = models.TextField(blank=True, default='')  # For technical users

    # Risk & Priority
    risk_score = models.IntegerField(default=0)  # 0-100 numerical score
    priority_rank = models.IntegerField(null=True, blank=True)  # Remediation priority
    endpoint_sensitivity = models.CharField(max_length=20, default='public')
    
    # Multi-Factor Confidence Scoring (integers 0-100 for clarity)
    pattern_confidence = models.IntegerField(default=0)   # 0-30: Pattern/signature detection
    response_confidence = models.IntegerField(default=0)  # 0-30: Response anomaly detection
    exploit_confidence = models.IntegerField(default=0)   # 0-30: Exploit confirmation
    context_confidence = models.IntegerField(default=0)   # 0-10: Context/sensitivity adjustment
    total_confidence = models.IntegerField(default=0)     # Sum, capped at 100
    
    # Validation Status (repurposed from action_taken)
    VALIDATION_CHOICES = [
        ('pending', 'Pending'),
        ('validated', 'Validated'),
        ('partial', 'Partially Validated'),
        ('failed', 'Not Validated'),
    ]
    validation_status = models.CharField(
        max_length=20, 
        choices=VALIDATION_CHOICES, 
        default='pending'
    )
    
    # Classification Label
    CLASSIFICATION_CHOICES = [
        ('confirmed', 'Confirmed Vulnerability'),
        ('likely', 'Likely Vulnerability'),
        ('suspicious', 'Suspicious Pattern'),
        ('informational', 'Informational'),
    ]
    classification = models.CharField(
        max_length=20, 
        choices=CLASSIFICATION_CHOICES, 
        default='suspicious'
    )

    # AI ML Classification Fields (New)
    ai_classification = models.CharField(max_length=100, blank=True, default='')
    ai_confidence = models.FloatField(default=0.0)
    detection_method = models.CharField(
        max_length=20,
        choices=[
            ('rule', 'Rule-Based'),
            ('ai', 'AI-Classified'),
            ('hybrid', 'Hybrid'),
        ],
        default='rule'
    )
    class_probabilities = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"{self.v_type} ({self.severity}) on {self.affected_url} [Confidence: {self.total_confidence}%]"


class RequestLog(models.Model):
    """Track requests for behavioral analysis (sliding window)."""
    source_ip = models.GenericIPAddressField()
    target_url = models.URLField()
    timestamp = models.DateTimeField(auto_now_add=True)
    request_hash = models.CharField(max_length=64)  # For pattern detection

    class Meta:
        indexes = [
            models.Index(fields=['source_ip', 'timestamp']),
        ]
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.source_ip} -> {self.target_url} at {self.timestamp}"


class ScannerMetrics(models.Model):
    """Track precision/recall metrics for scanner performance evaluation."""
    scan = models.OneToOneField(ScanHistory, on_delete=models.CASCADE, related_name='metrics')
    
    # Confusion matrix counts
    true_positives = models.IntegerField(default=0)
    false_positives = models.IntegerField(default=0)
    false_negatives = models.IntegerField(default=0)
    
    # Calculated metrics
    precision = models.FloatField(default=0.0)  # TP / (TP + FP)
    recall = models.FloatField(default=0.0)     # TP / (TP + FN)
    f1_score = models.FloatField(default=0.0)   # Harmonic mean
    
    # Benchmark info
    benchmark_source = models.CharField(max_length=100, blank=True, default='')
    evaluated_at = models.DateTimeField(auto_now=True)
    
    def calculate_metrics(self):
        """Recalculate precision, recall, and F1 score."""
        tp, fp, fn = self.true_positives, self.false_positives, self.false_negatives
        self.precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        self.recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        if self.precision + self.recall > 0:
            self.f1_score = 2 * (self.precision * self.recall) / (self.precision + self.recall)
        else:
            self.f1_score = 0.0
        self.save()
    
    def __str__(self):
        return f"Metrics for Scan {self.scan_id}: P={self.precision:.2f}, R={self.recall:.2f}"


# Signals
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.get_or_create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'profile'):
        instance.profile.save()