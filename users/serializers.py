# serializers.py
from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers
import secrets
from django.utils import timezone
from datetime import timedelta
from django.core.exceptions import ValidationError
import re
from django.core.mail import send_mail
from utils.some_util_file import validate_ecuadorian_cedula
import logging


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ['name', 'last_name', 'username', 'email', 'password', 'cedula', 'phone', 'address', 'city', 'country', 'birthday', 'role', 'email_confirmed']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_password(self, value):
        if len(value) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'\d', value):
            raise ValidationError("Password must contain at least one number.")
        if not re.search(r'[A-Z]', value):
            raise ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise ValidationError("Password must contain at least one special character.")
        return value

    def create(self, validated_data):
        validated_data['email_confirmed'] = False
        return get_user_model().objects.create_user(**validated_data)

class AuthTokenSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        user = authenticate(
            request=self.context.get('request'),
            username=email,
            password=password
        )
        if not user:
            raise serializers.ValidationError('Unable to log in with provided credentials.')

        if not user.is_active:
            raise serializers.ValidationError('Account is inactive.')

        # Generate and send verification code
        verification_code = user.generate_verification_code()
        subject = 'Login Verification Code'
        message = f'Your login verification code is: {verification_code}'
        send_mail(subject, message, 'no-reply@example.com', [user.email])

        # Return user without tokens; tokens will be provided upon verification
        attrs['user'] = user
        return attrs

class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField()

    def validate(self, attrs):
        token = attrs.get('token')
        new_password = attrs.get('new_password')

        try:
            user = get_user_model().objects.get(
                reset_password_token=token,
                reset_password_expires__gt=timezone.now()
            )
        except get_user_model().DoesNotExist:
            raise serializers.ValidationError("Invalid or expired token.")

        user.set_password(new_password)
        user.reset_password_token = None
        user.reset_password_expires = None
        user.save()

        return attrs
    
class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField()

    def validate(self, attrs):
        token = attrs.get('token')
        new_password = attrs.get('new_password')

        try:
            user = get_user_model().objects.get(reset_password_token=token, reset_password_expiry__gt=timezone.now())
        except get_user_model().DoesNotExist:
            raise serializers.ValidationError("Invalid or expired token.")

        user.set_password(new_password)
        user.reset_password_token = None
        user.reset_password_expiry = None
        user.save()

        return attrs
    
logger = logging.getLogger(__name__)

class EmailConfirmationSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate_token(self, value):
        logger.info(f"Attempting to validate token: {value}")
        try:
            user = get_user_model().objects.get(confirmation_token=value)
        except get_user_model().DoesNotExist:
            logger.error(f"Token not found: {value}")
            raise serializers.ValidationError("Invalid token.")
        
        user.email_confirmed = True
        user.is_active = True
        user.confirmation_token = None
        user.save()
        return value


class CedulaVerificationSerializer(serializers.Serializer):
    cedula = serializers.CharField()

    def validate_cedula(self, value):
        if not validate_ecuadorian_cedula(value):
            raise serializers.ValidationError("Invalid Ecuadorian ID.")
        return value
    
class VerifyLoginCodeSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField()

    def validate(self, attrs):
        email = attrs.get('email')
        code = attrs.get('code')

        try:
            user = get_user_model().objects.get(email=email, verification_code=code)
        except get_user_model().DoesNotExist:
            raise serializers.ValidationError("Invalid verification code.")

        attrs['user'] = user
        return attrs
    
class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def save(self):
        token = self.validated_data['token']
        new_password = self.validated_data['new_password']
        User = get_user_model()
        try:
            user = User.objects.get(reset_password_token=token)
            if timezone.now() > user.reset_password_expires:
                raise serializers.ValidationError("Token has expired.")
            user.set_password(new_password)
            user.reset_password_token = None
            user.reset_password_expires = None
            user.save()
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid token.")

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not self.get_user_by_email(value):
            raise serializers.ValidationError("User not found.")
        user = self.get_user_by_email(value)
        if user:
            user.reset_password_token = secrets.token_hex(16)
            user.reset_password_expires = timezone.now() + timedelta(hours=1)
            user.save()
            self.send_reset_email(user, value)
        return value

    def get_user_by_email(self, email):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None

    def send_reset_email(self, user, email):
        subject = 'Password Reset'
        message = f'Please use this token to reset your password: {user.reset_password_token}'
        send_mail(subject, message, 'no-reply@example.com', [email])

    def save(self):
        pass