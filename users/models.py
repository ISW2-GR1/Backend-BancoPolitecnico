from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
import secrets
from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta

class UserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('You must provide an email address.')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.confirmation_token = secrets.token_hex(16)
        user.is_active = False
        user.save(using=self._db)

        # Send confirmation email
        subject = 'Email Confirmation'
        message = f'Please use this link to confirm your email: http://your-website.com/confirm/{user.confirmation_token}/'
        from_email = 'info.iso50001@inn-energy.net'
        send_mail(subject, message, from_email, [email])

        return user
    
    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    username = models.CharField(max_length=50, unique=True)
    birthday = models.DateField(null=True)
    email = models.EmailField(max_length=150, unique=True, blank=False)
    cedula = models.CharField(max_length=10, unique=True) 
    phone = models.CharField(max_length=10, blank=True)
    address = models.CharField(max_length=150, blank=True)
    city = models.CharField(max_length=50, blank=True)
    country = models.CharField(max_length=50, blank=True) 
    role = models.CharField(max_length=50, default='2')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    reset_password_token = models.CharField(max_length=255, blank=True, null=True)
    reset_password_expires = models.DateTimeField(null=True)
    email_confirmed = models.BooleanField(default=False)
    confirmation_token = models.CharField(max_length=100, blank=True, null=True)
    verification_code = models.CharField(max_length=6, blank=True, null=True)
    verification_code_expiry = models.DateTimeField(null=True, blank=True)

    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def generate_verification_code(self):
        self.verification_code = secrets.token_hex(3)
        self.verification_code_expiry = timezone.now() + timedelta(minutes=10)
        self.save()
        return self.verification_code