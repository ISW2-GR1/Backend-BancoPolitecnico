from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers
from django.utils import timezone
from datetime import timedelta
from django.core.exceptions import ValidationError
import re
from django.core.mail import send_mail
import secrets
from .models import BankAccount, Contact, Transfer, TransferAudit
from utils.some_util_file import validate_ecuadorian_cedula
import logging
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)

######################################################################################################
### BANK ACCOUNT SERIALIZER ########

class BankAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankAccount
        fields = ['id', 'user', 'account_number', 'balance', 'is_active']
        read_only_fields = ['account_number', 'balance', 'user']

    def create(self, validated_data):
        user = self.context['request'].user
        validated_data.pop('user', None)
        validated_data.pop('account_number', None)
        account_number = generate_unique_account_number()
        bank_account = BankAccount.objects.create(user=user, account_number=account_number, **validated_data)
        return bank_account

######################################################################################################
### USER SERIALIZER ########

class UserSerializer(serializers.ModelSerializer):
    bank_accounts = BankAccountSerializer(many=True, read_only=True)
    contacts = serializers.SerializerMethodField()
    sent_transfers = serializers.SerializerMethodField()
    received_transfers = serializers.SerializerMethodField()
    available_balance = serializers.SerializerMethodField()
    account_numbers = serializers.SerializerMethodField()  # Nuevo campo

    class Meta:
        model = get_user_model()
        fields = ['name', 'last_name', 'username', 'email', 'password','cedula', 'phone', 'address', 'city', 'country', 'birthday', 'role', 'bank_accounts', 'contacts', 'sent_transfers', 'received_transfers', 'available_balance', 'account_numbers']
        extra_kwargs = {'password': {'write_only': True}}

    def get_contacts(self, obj):
        return ContactSerializer(obj.contacts.all(), many=True).data

    def get_sent_transfers(self, obj):
        return TransferSerializer(obj.sent_transfers.all(), many=True).data

    def get_received_transfers(self, obj):
        return TransferSerializer(obj.received_transfers.all(), many=True).data

    def get_available_balance(self, obj):
        bank_accounts = BankAccount.objects.filter(user=obj)
        total_balance = sum(account.balance for account in bank_accounts)
        return total_balance

    def get_account_numbers(self, obj):
        bank_accounts = BankAccount.objects.filter(user=obj)
        return [account.account_number for account in bank_accounts]
    
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
        return get_user_model().objects.create_user(**validated_data)

######################################################################################################
### CONTACT SERIALIZER ########

class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ['id', 'owner', 'contact', 'contact_account_number']

######################################################################################################
### AUTH TOKEN SERIALIZER ########

class AuthTokenSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'}, trim_whitespace=False)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        user = authenticate(request=self.context.get('request'), email=email, password=password)
        if not user:
            raise serializers.ValidationError('Unable to log in with provided credentials.')
        if not user.is_active:
            raise serializers.ValidationError('Account is inactive.')
        attrs['user'] = user
        return attrs


######################################################################################################
### PASSWORD RESET SERIALIZERS ########

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        user = self.get_user_by_email(value)
        if user:
            return value
        raise serializers.ValidationError("Usuario no encontrado.")

    def get_user_by_email(self, email):
        User = get_user_model()
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None

    def save(self):
        # Get the validated email
        email = self.validated_data['email']
        user = self.get_user_by_email(email)
        
        # Generate and set the reset password token
        user.reset_password_token = secrets.token_hex(16)
        user.reset_password_expires = timezone.now() + timedelta(hours=1)
        user.save()
        
        # Send the reset password email
        self.send_reset_email(user, email)

    def send_reset_email(self, user, email):
        reset_link = f'https://www.banco-politecnico.online/reset-password?token={user.reset_password_token}'
        subject = 'Restablecer tu contraseña'
        
        # Create HTML message
        html_message = f"""
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
                    <h1>Restablece tu contraseña</h1>
                    <p>Hola,</p>
                    <p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p>
                    <p><a href="{reset_link}">Restablecer mi contraseña</a></p>
                    <p>Si no has solicitado este cambio, puedes ignorar este correo.</p>
                    <div class="footer">
                        <p>Gracias,</p>
                        <p>El equipo de Banco Politécnico</p>
                    </div>
                </div>
            </body>
        </html>
        """
        
        # Create plain text message
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject,
            plain_message,
            'no-reply@example.com',
            [email],
            html_message=html_message
        )

###############################################################################################
##### Password Resent Confirmation ##############################

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

######################################################################################################
### EMAIL CONFIRMATION SERIALIZER ########

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

######################################################################################################
### CEDULA VERIFICATION SERIALIZER ########

class CedulaVerificationSerializer(serializers.Serializer):
    cedula = serializers.CharField()

    def validate_cedula(self, value):
        if not validate_ecuadorian_cedula(value):
            raise serializers.ValidationError("Invalid Ecuadorian ID.")
        return value

######################################################################################################
### VERIFY LOGIN CODE SERIALIZER ########

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

######################################################################################################
### TRANSFER SERIALIZER ########

class TransferSerializer(serializers.ModelSerializer):
    sender_account = serializers.CharField(write_only=True)
    receiver_account = serializers.CharField(write_only=True)

    class Meta:
        model = Transfer
        fields = ['sender_account', 'receiver_account', 'amount']

    def validate(self, data):
        sender_account_number = data.get('sender_account')
        receiver_account_number = data.get('receiver_account')
        
        # Obtener el usuario autenticado
        user = self.context['request'].user
        
        try:
            sender_account = BankAccount.objects.get(account_number=sender_account_number)
            receiver_account = BankAccount.objects.get(account_number=receiver_account_number)
        except BankAccount.DoesNotExist:
            raise serializers.ValidationError("Sender or receiver account does not exist.")

        # Verificar que el usuario autenticado es el propietario de la cuenta de origen
        if sender_account.user != user:
            raise serializers.ValidationError("You do not own the sender account.")

        # Opcional: Verificar que la cuenta de destino pertenece a otro usuario
        if receiver_account.user == user:
            raise serializers.ValidationError("You cannot transfer money to your own account.")
        
        return data

    def create(self, validated_data):
        sender_account_number = validated_data.pop('sender_account')
        receiver_account_number = validated_data.pop('receiver_account')

        sender_account = BankAccount.objects.get(account_number=sender_account_number)
        receiver_account = BankAccount.objects.get(account_number=receiver_account_number)

        transfer = Transfer.objects.create(
            sender=sender_account.user,
            receiver=receiver_account.user,
            amount=validated_data['amount'],
            is_confirmed=False
        )
        otp = transfer.generate_otp()

        # Enviar el código al correo del usuario
        send_mail(
            'Código de Confirmación para Transferencia de Dinero',
            f'Tu código de confirmación para la transferencia de dinero es {otp}',
            'no-reply@example.com',
            [transfer.sender.email]
        )

        return transfer
    
######################################################################################################
### CONFIRM TRANSFER SERIALIZER ########

class ConfirmTransferSerializer(serializers.Serializer):
    otp = serializers.CharField()

    def validate_otp(self, value):
        try:
            transfer = Transfer.objects.get(otp=value, otp_expiry__gt=timezone.now())
        except Transfer.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired OTP.")
        return value

    def save(self):
        otp = self.validated_data['otp']
        transfer = Transfer.objects.get(otp=otp)

        if transfer.is_confirmed:
            raise serializers.ValidationError("Transfer already confirmed.")

        transfer.is_confirmed = True
        transfer.save()

        # Obtener cuentas bancarias
        sender_account = BankAccount.objects.filter(user=transfer.sender).first()
        receiver_account = BankAccount.objects.filter(user=transfer.receiver).first()

        if not sender_account or not receiver_account:
            raise serializers.ValidationError("Sender or receiver account not found.")

        # Cantidades antes y después de la transferencia
        amount_before_sender = sender_account.balance
        amount_after_sender = amount_before_sender - transfer.amount
        amount_after_receiver = receiver_account.balance + transfer.amount

        # Actualizar el saldo de las cuentas
        sender_account.balance = amount_after_sender
        receiver_account.balance = amount_after_receiver
        sender_account.save()
        receiver_account.save()

        # Crear registro de auditoría
        TransferAudit.objects.create(
            transfer=transfer,
            sender_account=sender_account,
            receiver_account=receiver_account,
            amount=transfer.amount,
            amount_before_sender=amount_before_sender,
            amount_after_sender=amount_after_sender,
            amount_after_receiver=amount_after_receiver
        )

        return transfer
