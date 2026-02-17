# backend/api/views.py

from .tasks import run_web_scan

from .scanner.crawler import Crawler
from .scanner.scanners import VulnerabilityScanner
from .scanner.report_builder import ReportBuilder
from .scanner.pdf_generator import generate_pdf_report
import logging

logger = logging.getLogger(__name__)

from rest_framework import status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.http import HttpResponse
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import TokenError

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.db import transaction
from django.conf import settings

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from .models import EmailVerificationToken, PasswordResetToken, Profile, SocialAccount, ScanHistory, ScanFinding
from .serializers import (
    UserSerializer,
    RegisterSerializer,
    LoginSerializer,
    ChangePasswordSerializer,
    UpdateUserSerializer,
    VerifyEmailSerializer,
    ResendVerificationSerializer,
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    ValidateResetTokenSerializer,
    GoogleAuthSerializer,
    SocialAccountSerializer,
    ScanHistorySerializer,
    ScanFindingSerializer,
)
from .utils import send_verification_email, send_password_reset_email, send_password_changed_email



class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        verification_token = EmailVerificationToken.objects.create(user=user)
        
        try:
            send_verification_email(user, verification_token.token)
        except Exception as e:
            print(f"Error sending verification email: {e}")

        refresh = RefreshToken.for_user(user)

        return Response({
            'success': True,
            'message': 'Registration successful. Please check your email to verify your account.',
            'data': {
                'user': UserSerializer(user).data,
                'tokens': {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                }
            }
        }, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Invalid email or password'
            }, status=status.HTTP_401_UNAUTHORIZED)

        user = authenticate(username=user.username, password=password)

        if user is None:
            return Response({
                'success': False,
                'message': 'Invalid email or password'
            }, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_active:
            return Response({
                'success': False,
                'message': 'Account is disabled'
            }, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)
        is_verified = user.profile.is_email_verified if hasattr(user, 'profile') else False

        return Response({
            'success': True,
            'message': 'Login successful',
            'data': {
                'user': UserSerializer(user).data,
                'tokens': {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                },
                'is_email_verified': is_verified
            }
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()

            return Response({
                'success': True,
                'message': 'Logged out successfully'
            }, status=status.HTTP_200_OK)

        except TokenError:
            return Response({
                'success': False,
                'message': 'Invalid token'
            }, status=status.HTTP_400_BAD_REQUEST)


class UserView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method in ['PUT', 'PATCH']:
            return UpdateUserSerializer
        return UserSerializer

    def get_object(self):
        return self.request.user

    def retrieve(self, request, *args, **kwargs):
        serializer = self.get_serializer(request.user)
        return Response({
            'success': True,
            'data': serializer.data
        })

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        serializer = self.get_serializer(
            request.user,
            data=request.data,
            partial=partial
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            'success': True,
            'message': 'Profile updated successfully',
            'data': UserSerializer(request.user).data
        })


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user

        if not user.check_password(serializer.validated_data['old_password']):
            return Response({
                'success': False,
                'message': 'Current password is incorrect'
            }, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data['new_password'])
        user.save()

        try:
            send_password_changed_email(user)
        except Exception as e:
            logger.exception("Error sending password changed email")

        return Response({
            'success': True,
            'message': 'Password changed successfully'
        }, status=status.HTTP_200_OK)


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)
            return Response({
                'success': True,
                'data': {
                    'tokens': response.data
                }
            })
        except TokenError as e:
            return Response({
                'success': False,
                'message': str(e)
            }, status=status.HTTP_401_UNAUTHORIZED)



class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data['token']

        try:
            verification_token = EmailVerificationToken.objects.get(token=token)
        except EmailVerificationToken.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Invalid verification token'
            }, status=status.HTTP_400_BAD_REQUEST)

        if verification_token.is_used:
            return Response({
                'success': False,
                'message': 'This token has already been used'
            }, status=status.HTTP_400_BAD_REQUEST)

        if verification_token.is_expired():
            return Response({
                'success': False,
                'message': 'This token has expired. Please request a new verification email.'
            }, status=status.HTTP_400_BAD_REQUEST)

        verification_token.is_used = True
        verification_token.save()

        user = verification_token.user
        if hasattr(user, 'profile'):
            user.profile.is_email_verified = True
            user.profile.save()

        return Response({
            'success': True,
            'message': 'Email verified successfully'
        }, status=status.HTTP_200_OK)


class ResendVerificationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResendVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({
                'success': True,
                'message': 'If an account with this email exists, a verification email has been sent.'
            }, status=status.HTTP_200_OK)

        if hasattr(user, 'profile') and user.profile.is_email_verified:
            return Response({
                'success': False,
                'message': 'This email is already verified'
            }, status=status.HTTP_400_BAD_REQUEST)

        EmailVerificationToken.objects.filter(user=user, is_used=False).update(is_used=True)
        verification_token = EmailVerificationToken.objects.create(user=user)

        try:
            send_verification_email(user, verification_token.token)
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to send verification email. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            'success': True,
            'message': 'Verification email sent successfully'
        }, status=status.HTTP_200_OK)



class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
            PasswordResetToken.objects.filter(user=user, is_used=False).update(is_used=True)
            reset_token = PasswordResetToken.objects.create(user=user)

            try:
                sent = send_password_reset_email(user, reset_token.token)
                if sent:
                    logger.info(f"Password reset email sent to {user.email} (token={reset_token.token})")
                else:
                    logger.warning(f"Password reset email not sent to {user.email} (token={reset_token.token}). SMTP may be unavailable.")
            except Exception as e:
                logger.exception("Error sending password reset email")

        except User.DoesNotExist:
            pass

        return Response({
            'success': True,
            'message': 'If an account with this email exists, a password reset link has been sent.'
        }, status=status.HTTP_200_OK)


class ValidateResetTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ValidateResetTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data['token']

        try:
            reset_token = PasswordResetToken.objects.get(token=token)
        except PasswordResetToken.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Invalid reset token'
            }, status=status.HTTP_400_BAD_REQUEST)

        if not reset_token.is_valid():
            message = 'This token has expired' if reset_token.is_expired() else 'This token has already been used'
            return Response({
                'success': False,
                'message': message
            }, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            'success': True,
            'message': 'Token is valid',
            'data': {
                'email': reset_token.user.email
            }
        }, status=status.HTTP_200_OK)


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data['token']
        password = serializer.validated_data['password']

        try:
            reset_token = PasswordResetToken.objects.get(token=token)
        except PasswordResetToken.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Invalid reset token'
            }, status=status.HTTP_400_BAD_REQUEST)

        if reset_token.is_used:
            return Response({
                'success': False,
                'message': 'This token has already been used'
            }, status=status.HTTP_400_BAD_REQUEST)

        if reset_token.is_expired():
            return Response({
                'success': False,
                'message': 'This token has expired. Please request a new password reset.'
            }, status=status.HTTP_400_BAD_REQUEST)

        user = reset_token.user
        user.set_password(password)
        user.save()

        reset_token.is_used = True
        reset_token.save()

        try:
            send_password_changed_email(user)
        except Exception as e:
            print(f"Error sending password changed email: {e}")

        return Response({
            'success': True,
            'message': 'Password reset successfully. You can now log in with your new password.'
        }, status=status.HTTP_200_OK)


class GoogleAuthView(APIView):
    """
    Google OAuth authentication view.
    Accepts Google ID token OR Access token and returns JWT tokens.
    """
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request):
        serializer = GoogleAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        credential = serializer.validated_data['credential']
        
        idinfo = None
        email = None
        
        try:
            # 1. Attempt to verify as a Google ID token (JWT)
            idinfo = id_token.verify_oauth2_token(
                credential,
                google_requests.Request(),
                settings.GOOGLE_CLIENT_ID
            )
            
            # Check if token is issued by Google
            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                return Response({
                    'success': False,
                    'message': 'Invalid token issuer'
                }, status=status.HTTP_400_BAD_REQUEST)

            google_user_id = idinfo['sub']
            email = idinfo.get('email')
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')
            picture = idinfo.get('picture', '')
            email_verified = idinfo.get('email_verified', False)

        except (ValueError, KeyError, TypeError):
            # 2. If ID token verification fails, attempt to treat as an Access Token
            # Fetch user info manually from Google
            import requests as py_requests
            try:
                userinfo_response = py_requests.get(
                    'https://www.googleapis.com/oauth2/v3/userinfo',
                    headers={'Authorization': f'Bearer {credential}'},
                    timeout=10
                )
                
                if userinfo_response.status_code != 200:
                    return Response({
                        'success': False,
                        'message': 'Invalid Google token (neither valid ID token nor valid Access token)'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                user_info = userinfo_response.json()
                google_user_id = user_info.get('sub')
                email = user_info.get('email')
                first_name = user_info.get('given_name', '')
                last_name = user_info.get('family_name', '')
                picture = user_info.get('picture', '')
                email_verified = user_info.get('email_verified', True) # Access tokens from success response are verified
                
            except Exception as e:
                return Response({
                    'success': False,
                    'message': f'Failed to verify access token: {str(e)}'
                }, status=status.HTTP_400_BAD_REQUEST)

        if not email:
            return Response({
                'success': False,
                'message': 'Email not provided by Google'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Proceed with user lookup and login
        try:
            # Check if social account already exists
            try:
                social_account = SocialAccount.objects.get(
                    provider='google',
                    provider_id=google_user_id
                )
                user = social_account.user
                created = False

            except SocialAccount.DoesNotExist:
                # Check if user with this email exists
                try:
                    user = User.objects.get(email=email)
                    created = False
                except User.DoesNotExist:
                    # Create new user
                    user = User.objects.create(
                        username=email,
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                    )
                    # Set unusable password for social login users
                    user.set_unusable_password()
                    user.save()
                    created = True

                # Create social account link
                SocialAccount.objects.create(
                    user=user,
                    provider='google',
                    provider_id=google_user_id,
                    extra_data={
                        'email': email,
                        'first_name': first_name,
                        'last_name': last_name,
                        'picture': picture,
                    }
                )

            # Update user profile
            if hasattr(user, 'profile'):
                if email_verified:
                    user.profile.is_email_verified = True
                if picture and not user.profile.avatar:
                    user.profile.avatar = picture
                user.profile.save()

            # Update user info if needed
            if not user.first_name and first_name:
                user.first_name = first_name
            if not user.last_name and last_name:
                user.last_name = last_name
            user.save()

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)

            return Response({
                'success': True,
                'message': 'Google login successful',
                'data': {
                    'user': UserSerializer(user).data,
                    'tokens': {
                        'access': str(refresh.access_token),
                        'refresh': str(refresh),
                    },
                    'created': created,
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'success': False,
                'message': f'Google authentication failed: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SocialAccountsView(generics.ListAPIView):
    """
    List connected social accounts for current user.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = SocialAccountSerializer

    def get_queryset(self):
        return SocialAccount.objects.filter(user=self.request.user)

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data
        })


class DisconnectSocialAccountView(APIView):
    """
    Disconnect a social account from user.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, provider):
        user = request.user

        # Check if user has a password set (can still login without social)
        if not user.has_usable_password():
            # Check if this is the only social account
            social_accounts = SocialAccount.objects.filter(user=user)
            if social_accounts.count() <= 1:
                return Response({
                    'success': False,
                    'message': 'Cannot disconnect the only login method. Please set a password first.'
                }, status=status.HTTP_400_BAD_REQUEST)

        try:
            social_account = SocialAccount.objects.get(user=user, provider=provider)
            social_account.delete()

            return Response({
                'success': True,
                'message': f'{provider.title()} account disconnected successfully'
            }, status=status.HTTP_200_OK)

        except SocialAccount.DoesNotExist:
            return Response({
                'success': False,
                'message': f'No {provider.title()} account connected'
            }, status=status.HTTP_404_NOT_FOUND)


# ============================================
# SCANNER VIEWS
# ============================================

class ScanView(APIView):
    """
    API endpoint to initiate a web vulnerability scan asynchronously.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        target_url = request.data.get('target_url')
        
        if not target_url:
            return Response({
                'success': False,
                'message': 'Target URL is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        if not target_url.startswith(('http://', 'https://')):
            return Response({
                'success': False,
                'message': 'Invalid URL format'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # 1. Create ScanHistory record
            scan_history = ScanHistory.objects.create(
                user=request.user,
                target_url=target_url,
                status='Pending'
            )

            # 2. Trigger async task
            run_web_scan.delay(scan_history.id, target_url)

            return Response({
                'success': True,
                'message': 'Scan initiated successfully',
                'data': {
                    'scan_id': scan_history.id,
                    'status': 'Pending'
                }
            }, status=status.HTTP_202_ACCEPTED)

        except Exception as e:
            return Response({
                'success': False,
                'message': f'Scan initiation failed: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ScanHistoryView(generics.ListAPIView):
    """
    List all scans for the authenticated user.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = ScanHistorySerializer

    def get_queryset(self):
        return ScanHistory.objects.filter(user=self.request.user)

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'success': True,
            'data': serializer.data
        })


class ScanResultView(generics.RetrieveAPIView):
    """
    Retrieve detailed results for a specific scan.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = ScanHistorySerializer

    def get_queryset(self):
        return ScanHistory.objects.filter(user=self.request.user)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({
            'success': True,
            'data': serializer.data
        })


class ScanDashboardStatsView(APIView):
    """
    Enhanced Dashboard Statistics Endpoint.
    Returns:
    - Repository Risk Score (0-100)
    - Vulnerability Counts (by severity)
    - Top Prioritized Fixes (AI-ranked)
    - Recent Activity Summary
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        
        # 1. Get latest scan for each unique target (to avoid double counting)
        # We need a robust way to get "current state".
        # For simplicity MVP: just take all successful scans from the last 30 days?
        # Better: Group by target_url and max(timestamp).
        
        # Determine unique targets
        unique_targets = ScanHistory.objects.filter(
            user=user, 
            status='Completed'
        ).values_list('target_url', flat=True).distinct()
        
        latest_scans_ids = []
        for url in unique_targets:
            latest = ScanHistory.objects.filter(
                user=user, 
                target_url=url, 
                status='Completed'
            ).order_by('-timestamp').first()
            if latest:
                latest_scans_ids.append(latest.id)
                
        # 2. Get all findings from these latest scans
        active_findings = ScanFinding.objects.filter(scan_id__in=latest_scans_ids)
        
        # 3. Calculate Repository Risk Score
        # Start at 100
        # High: -15, Medium: -5, Low: -1
        risk_score = 100
        
        high_count = active_findings.filter(severity='High').count()
        medium_count = active_findings.filter(severity='Medium').count()
        low_count = active_findings.filter(severity='Low').count()
        
        risk_deduction = (high_count * 15) + (medium_count * 5) + (low_count * 1)
        risk_score = max(0, risk_score - risk_deduction)
        
        # 4. Get Top Prioritized Fixes
        # Use priority_rank if available, otherwise fallback to risk_score
        top_fixes_qs = active_findings.order_by('priority_rank', '-risk_score')[:5]
        top_fixes = ScanFindingSerializer(top_fixes_qs, many=True).data
        
        # 5. Recent Activity (Last 5 scans)
        recent_scans_qs = ScanHistory.objects.filter(user=user).order_by('-timestamp')[:5]
        recent_scans = ScanHistorySerializer(recent_scans_qs, many=True).data
        
        return Response({
            'success': True,
            'data': {
                'risk_score': risk_score,
                'counts': {
                    'High': high_count,
                    'Medium': medium_count,
                    'Low': low_count,
                    'Total': active_findings.count()
                },
                'top_fixes': top_fixes,
                'recent_scans': recent_scans,
                'active_targets': len(unique_targets)
            }
        })


class DownloadReportView(APIView):
    """
    Download scan report as a styled PDF.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        try:
            scan = ScanHistory.objects.get(id=scan_id, user=request.user)

            pdf_buffer = generate_pdf_report(scan)

            response = HttpResponse(
                pdf_buffer.getvalue(),
                content_type='application/pdf'
            )

            response['Content-Disposition'] = (
                f'attachment; filename="arhmora_report_{scan_id}.pdf"'
            )

            return response

        except ScanHistory.DoesNotExist:
            return Response(
                {"error": "Scan not found"},
                status=404
            )
