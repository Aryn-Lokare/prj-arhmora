# backend/api/urls.py

from django.urls import path
from .views import (
    # Auth
    RegisterView,
    LoginView,
    LogoutView,
    UserView,
    ChangePasswordView,
    CustomTokenRefreshView,
    # Email Verification
    VerifyEmailView,
    ResendVerificationView,
    # Password Reset
    ForgotPasswordView,
    ValidateResetTokenView,
    ResetPasswordView,
)

urlpatterns = [
    # Auth endpoints
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('auth/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('auth/user/', UserView.as_view(), name='user'),
    path('auth/change-password/', ChangePasswordView.as_view(), name='change_password'),
    
    # Email verification endpoints
    path('auth/verify-email/', VerifyEmailView.as_view(), name='verify_email'),
    path('auth/resend-verification/', ResendVerificationView.as_view(), name='resend_verification'),
    
    # Password reset endpoints
    path('auth/forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('auth/validate-reset-token/', ValidateResetTokenView.as_view(), name='validate_reset_token'),
    path('auth/reset-password/', ResetPasswordView.as_view(), name='reset_password'),
]
