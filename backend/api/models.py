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

    # New fields for enhanced architecture
    risk_score = models.IntegerField(default=0)  # 0-100 numerical score
    confidence = models.FloatField(default=0.0)  # AI confidence 0.0-1.0
    priority_rank = models.IntegerField(null=True, blank=True)  # Remediation priority
    endpoint_sensitivity = models.CharField(max_length=20, default='public')
    action_taken = models.CharField(max_length=20, default='flagged')  # block/throttle/allow/flagged

    def __str__(self):
        return f"{self.v_type} ({self.severity}) on {self.affected_url} [Risk: {self.risk_score}]"


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