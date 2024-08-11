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
import random
import string
from django.core.mail import EmailMessage

class UserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('You must provide an email address.')
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.confirmation_token = secrets.token_hex(16)
        user.is_active = False
        user.save(using=self._db)
        subject = 'Confirmación de Correo Electrónico'
        message = f"""
            <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f4;
                        color: #333;
                        margin: 0;
                        padding: 20px;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: auto;
                        background-color: #fff;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    }}
                    h1 {{
                        color: #007BFF;
                    }}
                    p {{
                        font-size: 16px;
                    }}
                    a {{
                        color: #007BFF;
                        text-decoration: none;
                        font-weight: bold;
                    }}
                    .footer {{
                        margin-top: 20px;
                        font-size: 14px;
                        color: #777;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Confirmación de Correo Electrónico</h1>
                    <p>Hola,</p>
                    <p>Para completar el registro de tu cuenta, por favor confirma tu correo electrónico haciendo clic en el siguiente enlace:</p>
                    <p><a href="https://www.banco-politecnico.online/confirm/{user.confirmation_token}/">Confirmar mi correo electrónico</a></p>
                    <p>Si no te has registrado en nuestro sitio, puedes ignorar este mensaje.</p>
                    <div class="footer">
                        <p>Gracias,</p>
                        <p>El equipo de Banco Politécnico</p>
                    </div>
                </div>
            </body>
            </html>
            """
        from_email = 'info.iso50001@inn-energy.net'
        email = EmailMessage(subject, message, from_email, [email])
        email.content_subtype = 'html'
        email.send()

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
    email = models.EmailField(max_length=150, unique=True)
    cedula = models.CharField(max_length=10, unique=True) 
    phone = models.CharField(max_length=10, blank=True)
    address = models.CharField(max_length=150, blank=True)
    city = models.CharField(max_length=50, blank=True)
    country = models.CharField(max_length=50, blank=True)
    role = models.CharField(max_length=50, default='2')
    is_active = models.BooleanField(default=False)  # Default to False until confirmed
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
    is_primary = models.BooleanField(default=False)

    def __str__(self):
        return f'{self.user.username} - {self.account_number}'

class Contact(models.Model):
    owner = models.ForeignKey(User, related_name='contacts', on_delete=models.CASCADE)
    contact = models.ForeignKey(User, on_delete=models.CASCADE)
    contact_account_number = models.CharField(max_length=20)
    is_active = models.BooleanField(default=True)  # Nuevo campo

    def __str__(self):
        return f'{self.owner.username} - {self.contact.username}'


class Transfer(models.Model):
    sender = models.ForeignKey(User, related_name='sent_transfers', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_transfers', on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    timestamp = models.DateTimeField(default=timezone.now)
    is_confirmed = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_expiry = models.DateTimeField(null=True, blank=True)
    concept = models.CharField(max_length=255, blank=True, null=True)
    document_number = models.CharField(max_length=50, blank=True, null=True)
    
    sender_account_number = models.CharField(max_length=20, blank=True, null=True)
    receiver_account_number = models.CharField(max_length=20, blank=True, null=True)

    def generate_otp(self):
        self.otp = ''.join(random.choices(string.digits, k=6))
        self.otp_expiry = timezone.now() + timedelta(minutes=10)
        self.save()
        return self.otp

    def is_otp_valid(self, otp):
        return self.otp == otp and timezone.now() <= self.otp_expiry

class TransferAudit(models.Model):
    transfer = models.OneToOneField(Transfer, on_delete=models.CASCADE)
    sender_account_number = models.CharField(max_length=20)
    receiver_account_number = models.CharField(max_length=20)
    sender_username = models.CharField(max_length=150)
    receiver_username = models.CharField(max_length=150)
    amount_before = models.DecimalField(max_digits=10, decimal_places=2)
    amount_after_sender = models.DecimalField(max_digits=10, decimal_places=2)
    amount_after_receiver = models.DecimalField(max_digits=10, decimal_places=2)
    action = models.CharField(max_length=50)
    timestamp = models.DateTimeField(auto_now_add=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        verbose_name = "Transfer Audit"
        verbose_name_plural = "Transfer Audits"
