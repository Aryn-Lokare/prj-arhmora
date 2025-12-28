import os
import django
from django.core.mail import send_mail
from django.conf import settings

# Setup Django atmosphere
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')
django.setup()

def test_email():
    print(f"Testing email sending with BACKEND: {settings.EMAIL_BACKEND}")
    print(f"SMTP Host: {settings.EMAIL_HOST}:{settings.EMAIL_PORT}")
    print(f"From Email: {settings.DEFAULT_FROM_EMAIL}")
    
    try:
        # We'll try to send a test email to the configured EMAIL_HOST_USER
        recipient = settings.EMAIL_HOST_USER
        if not recipient:
            print("ERROR: EMAIL_HOST_USER is not set in .env")
            return

        send_mail(
            'Test Email from Arhmora',
            'This is a test email to verify your SMTP configuration is working correctly.',
            settings.DEFAULT_FROM_EMAIL,
            [recipient],
            fail_silently=False,
        )
        print(f"SUCCESS: Email sent successfully to {recipient}!")
    except Exception as e:
        print(f"FAILED: Could not send email. Error: {e}")

if __name__ == "__main__":
    test_email()
