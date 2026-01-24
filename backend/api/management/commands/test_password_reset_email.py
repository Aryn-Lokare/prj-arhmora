import logging

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from api.models import PasswordResetToken
from api.utils import send_password_reset_email

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Send a test password reset email to a user by email address.'

    def add_arguments(self, parser):
        parser.add_argument('--email', type=str, required=True, help='Email address of the user to send password reset email to')

    def handle(self, *args, **options):
        email = options['email']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(f'User with email {email} does not exist.'))
            return

        # Invalidate any existing unused tokens for clean testing
        PasswordResetToken.objects.filter(user=user, is_used=False).update(is_used=True)
        reset_token = PasswordResetToken.objects.create(user=user)

        try:
            sent = send_password_reset_email(user, reset_token.token)
            if sent:
                self.stdout.write(self.style.SUCCESS(
                    f'Password reset email sent to {user.email} (token={reset_token.token})'
                ))
            else:
                self.stdout.write(self.style.WARNING(
                    f'Password reset email not sent to {user.email}. SMTP may be unavailable.'
                ))
        except Exception as e:
            logger.exception("Failed to send password reset email during test")
            self.stdout.write(self.style.ERROR(f'Error sending password reset email: {e}'))
