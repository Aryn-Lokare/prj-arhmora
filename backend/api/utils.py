# backend/api/utils.py

from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings


def send_verification_email(user, token):
    """Send email verification email"""
    
    subject = 'Verify your email address'
    verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    
    # Render HTML template
    html_content = render_to_string('emails/verification.html', {
        'user': user,
        'verification_url': verification_url,
        'expiry_hours': settings.EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS,
    })
    
    # Create plain text version
    text_content = strip_tags(html_content)
    
    # Create email
    email = EmailMultiAlternatives(
        subject=subject,
        body=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[user.email]
    )
    email.attach_alternative(html_content, "text/html")
    
    # Send email
    email.send(fail_silently=False)


def send_password_reset_email(user, token):
    """Send password reset email"""
    
    subject = 'Reset your password'
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    
    # Render HTML template
    html_content = render_to_string('emails/password_reset.html', {
        'user': user,
        'reset_url': reset_url,
        'expiry_hours': settings.PASSWORD_RESET_TOKEN_EXPIRY_HOURS,
    })
    
    # Create plain text version
    text_content = strip_tags(html_content)
    
    # Create email
    email = EmailMultiAlternatives(
        subject=subject,
        body=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[user.email]
    )
    email.attach_alternative(html_content, "text/html")
    
    # Send email
    return email.send(fail_silently=False)


def send_password_changed_email(user):
    """Send notification that password was changed"""
    
    subject = 'Your password has been changed'
    
    html_content = render_to_string('emails/password_changed.html', {
        'user': user,
    })
    
    text_content = strip_tags(html_content)
    
    email = EmailMultiAlternatives(
        subject=subject,
        body=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[user.email]
    )
    email.attach_alternative(html_content, "text/html")
    
    email.send(fail_silently=False)

    
