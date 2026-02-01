# backend/api/serializers.py

from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import Profile, SocialAccount, ScanHistory, ScanFinding


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ('is_email_verified', 'phone', 'avatar', 'bio')
        read_only_fields = ('is_email_verified',)


class UserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(read_only=True)
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'date_joined', 'profile')
        read_only_fields = ('id', 'date_joined')


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ('email', 'password', 'password2', 'first_name', 'last_name')

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Passwords don't match."})
        
        try:
            validate_password(attrs['password'])
        except ValidationError as e:
            raise serializers.ValidationError({"password": list(e.messages)})
        
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['email'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    new_password2 = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError({"new_password": "Passwords don't match."})
        
        try:
            validate_password(attrs['new_password'])
        except ValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)})
        
        return attrs


class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email')
    
    def validate_email(self, value):
        user = self.context['request'].user
        if User.objects.exclude(pk=user.pk).filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value


# Email Verification Serializers
class VerifyEmailSerializer(serializers.Serializer):
    token = serializers.UUIDField(required=True)


class ResendVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


# Password Reset Serializers
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.UUIDField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    password2 = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Passwords don't match."})
        
        try:
            validate_password(attrs['password'])
        except ValidationError as e:
            raise serializers.ValidationError({"password": list(e.messages)})
        
        return attrs


class ValidateResetTokenSerializer(serializers.Serializer):
    token = serializers.UUIDField(required=True)


class GoogleAuthSerializer(serializers.Serializer):
    """Serializer for Google OAuth token"""
    
    credential = serializers.CharField(required=True, help_text="Google ID token")


class SocialAccountSerializer(serializers.ModelSerializer):
    """Serializer for social accounts"""
    class Meta:
        model = SocialAccount
        fields = ('id', 'provider', 'created_at')
        read_only_fields = ('id', 'provider', 'created_at')


class ScanFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanFinding
        fields = (
            'id', 'v_type', 'severity', 'affected_url', 'evidence', 'remediation',
            'remediation_simple', 'remediation_technical',
            # AI-generated explanations
            'explanation_simple', 'explanation_technical',
            'risk_score', 'priority_rank', 'endpoint_sensitivity',
            # Multi-factor confidence fields
            'pattern_confidence', 'response_confidence', 'exploit_confidence',
            'context_confidence', 'total_confidence',
            'validation_status', 'classification',
        )


class ScanHistorySerializer(serializers.ModelSerializer):
    findings = ScanFindingSerializer(many=True, read_only=True)
    
    class Meta:
        model = ScanHistory
        fields = ('id', 'target_url', 'timestamp', 'status', 'task_id', 'findings')
        read_only_fields = ('id', 'timestamp', 'status', 'task_id')