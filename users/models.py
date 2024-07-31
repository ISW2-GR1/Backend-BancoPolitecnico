from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser, 
    PermissionsMixin, 
    BaseUserManager
)

import secrets
from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta
from django.conf import settings

class UserManager(BaseUserManager):
    
    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('You must provide an email address.')
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
    
    def create_superuser(self, email, password):
        user = self.create_user(email, password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        
        return  user
        
    
    
class User(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    username = models.CharField(max_length=50, unique=True)
    birthday = models.DateField(null=True)
    email = models.EmailField(max_length=150, unique=True, blank=False)
    password = models.CharField(max_length=150)
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

    def generate_verification_code(self):
        self.verification_code = secrets.token_hex(3)
        self.verification_code_expiry = timezone.now() + timedelta(minutes=10)
        self.save()
        return self.verification_code
    objects = UserManager()
    
    USERNAME_FIELD ='email'

class BankAccount(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    account_number = models.CharField(max_length=20, unique=True)
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f'{self.user.username} - {self.account_number}'


class Contact(models.Model):
    owner = models.ForeignKey(User, related_name='contacts', on_delete=models.CASCADE)
    contact = models.ForeignKey(User, on_delete=models.CASCADE)
    contact_account_number = models.CharField(max_length=20)