from django.contrib.auth import get_user_model, authenticate
from rest_framework import generics, permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.conf import settings
from django.db import transaction
import secrets
from django.db.models import Prefetch

from users.serializers import (
    UserSerializer, AuthTokenSerializer, BankAccountSerializer,
    TransferSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer,
    EmailConfirmationSerializer, CedulaVerificationSerializer, VerifyLoginCodeSerializer, ConfirmTransferSerializer
)
from .models import BankAccount, Transfer,Contact
from .signals import generate_unique_account_number
from .models import User

###################################################################################
##### CREATE USER
class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    def perform_create(self, serializer):
        
        serializer.save()
        
###################################################################################
##### VIEW AND UPDATE USERS
class RetrieveUpdateUserView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        user = self.request.user
        user = get_user_model().objects.prefetch_related(
            Prefetch('bankaccount_set', queryset=BankAccount.objects.all()),
            Prefetch('contacts', queryset=Contact.objects.all()),
            Prefetch('sent_transfers', queryset=Transfer.objects.all()),
            Prefetch('received_transfers', queryset=Transfer.objects.all())
        ).get(id=user.id)

        return user

    def get(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user)
        return Response(serializer.data)
    

###################################################################################
########### CREATE TOKEN
class CreateTokenView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(request=request, username=email, password=password)
        if not user:
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

        if not user.is_active:
            return Response({'detail': 'Account is inactive'}, status=status.HTTP_400_BAD_REQUEST)

        verification_code = secrets.token_hex(6)
        user.verification_code = verification_code
        user.save()

        subject = 'Your Login Verification Code'
        message = f'Your new verification code is: {verification_code}'
        send_mail(subject, message, 'no-reply@example.com', [user.email])

        return Response({"detail": "Verification code sent to your email."})

###################################################################################
###### LOGOUT
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response(status=status.HTTP_204_NO_CONTENT)

###################################################################################
###### PASSWORD RESET
class PasswordResetView(generics.CreateAPIView):
    serializer_class = PasswordResetSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password reset email sent.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

###################################################################################
###### PASSWORD RESET CONFIRM
class PasswordResetConfirmView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

###################################################################################
###### EMAIL CONFIRMATION
class EmailConfirmationView(generics.GenericAPIView):
    serializer_class = EmailConfirmationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"detail": "Email confirmed successfully."})
    
###################################################################################
###### VERIFY LOGIN CODE
class VerifyLoginCodeView(APIView):
    serializer_class = VerifyLoginCodeSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        code = serializer.validated_data['code']

        try:
            user = get_user_model().objects.get(email=email, verification_code=code)
        except get_user_model().DoesNotExist:
            return Response({"detail": "Invalid verification code"}, status=status.HTTP_400_BAD_REQUEST)

        user.verification_code = None
        user.save()

        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

###################################################################################
###### CEDULA VERIFICATION
class CedulaVerificationView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = CedulaVerificationSerializer(data=request.data)
        if serializer.is_valid():
            return Response({"message": "Cedula es válida."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
###################################################################################
###### BANK ACCOUNTS
class BankAccountViewSet(viewsets.ModelViewSet):
    queryset = BankAccount.objects.all()
    serializer_class = BankAccountSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return BankAccount.objects.filter(user=self.request.user)

###################################################################################
###### CONFIRM TRANSFER
from .models import Transfer
from django.utils.timezone import now
from rest_framework.permissions import IsAuthenticated
class ConfirmTransferView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = ConfirmTransferSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        transfer = serializer.save()

        # Obtener detalles de las cuentas
        sender_accounts = BankAccount.objects.filter(user=transfer.sender)
        receiver_accounts = BankAccount.objects.filter(user=transfer.receiver)

        if not sender_accounts.exists() or not receiver_accounts.exists():
            return Response({"detail": "No se encontraron cuentas para el remitente o destinatario."}, status=status.HTTP_404_NOT_FOUND)

        # Usar la primera cuenta si hay varias
        sender_account = sender_accounts.first()
        receiver_account = receiver_accounts.first()

        cuenta_origen = 'XXXXXX' + sender_account.account_number[-4:]
        cuenta_destino = 'XXXXXX' + receiver_account.account_number[-4:]

        # Obtener la fecha y hora actual
        fecha_actual = now().strftime('%A, %d de %B de %Y %H:%M')

        # Mensaje para el remitente
        mensaje_remitente = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    color: #333;
                    margin: 0;
                    padding: 0;
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
                    font-size: 24px;
                    margin-bottom: 20px;
                }}
                p {{
                    font-size: 16px;
                    line-height: 1.5;
                    margin: 0 0 15px;
                }}
                .details {{
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .details h2 {{
                    font-size: 18px;
                    color: #007BFF;
                    margin: 0 0 10px;
                }}
                .footer {{
                    margin-top: 20px;
                    font-size: 14px;
                    color: #777;
                    text-align: center;
                }}
                .button {{
                    display: inline-block;
                    padding: 10px 20px;
                    font-size: 16px;
                    color: #fff;
                    background-color: #007BFF;
                    text-decoration: none;
                    border-radius: 5px;
                    margin-top: 10px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>¡Transferencia Realizada con Éxito!</h1>
                <p>Hola {transfer.sender.name.upper()},</p>
                <p>Tu transferencia ha sido realizada con éxito. Aquí están los detalles:</p>
                <div class="details">
                    <h2>Detalles de la Transferencia</h2>
                    <p><strong>Cuenta de Origen:</strong> {cuenta_origen}</p>
                    <p><strong>Cuenta Acreditada:</strong> {cuenta_destino}</p>
                    <p><strong>Nombre del Beneficiario:</strong> {transfer.receiver.name.upper()} {transfer.receiver.last_name.upper()}</p>
                    <p><strong>Monto:</strong> USD {transfer.amount:.2f}</p>
                    <p><strong>Fecha:</strong> {now().strftime('%d/%m/%Y')}</p>
                </div>
                <p>Si no has solicitado este servicio, por favor repórtalo a nuestra Banca Telefónica al (02)2999 999.</p>
                <p>Gracias por utilizar nuestros servicios.</p>
                <div class="footer">
                    <p>Atentamente,</p>
                    <p>El equipo de Banco Politécnico</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Enviar correo al remitente
        send_mail(
            'Transferencia realizada exitosamente',
            mensaje_remitente,
            'no-reply@example.com',
            [transfer.sender.email],
            fail_silently=False,
            html_message=mensaje_remitente
        )

        # Mensaje para el destinatario
        mensaje_destinatario = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    color: #333;
                    margin: 0;
                    padding: 0;
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
                    font-size: 24px;
                    margin-bottom: 20px;
                }}
                p {{
                    font-size: 16px;
                    line-height: 1.5;
                    margin: 0 0 15px;
                }}
                .details {{
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .details h2 {{
                    font-size: 18px;
                    color: #007BFF;
                    margin: 0 0 10px;
                }}
                .footer {{
                    margin-top: 20px;
                    font-size: 14px;
                    color: #777;
                    text-align: center;
                }}
                .button {{
                    display: inline-block;
                    padding: 10px 20px;
                    font-size: 16px;
                    color: #fff;
                    background-color: #007BFF;
                    text-decoration: none;
                    border-radius: 5px;
                    margin-top: 10px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>¡Transferencia Recibida!</h1>
                <p>Hola {transfer.receiver.name.upper()},</p>
                <p>Has recibido una transferencia de {transfer.sender.name.upper()} {transfer.sender.last_name.upper()}. Aquí están los detalles:</p>
                <div class="details">
                    <h2>Detalles de la Transferencia</h2>
                    <p><strong>Cuenta Acreditada:</strong> {cuenta_destino}</p>
                    <p><strong>Monto:</strong> USD {transfer.amount:.2f}</p>
                </div>
                <p>Si no has solicitado este servicio, por favor repórtalo a nuestra Banca Telefónica al (02)2999 999.</p>
                <p>Gracias por utilizar nuestros servicios.</p>
                <div class="footer">
                    <p>Atentamente,</p>
                    <p>El equipo de Banco Politécnico</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Enviar correo al destinatario
        send_mail(
            'Has recibido una transferencia',
            mensaje_destinatario,
            'no-reply@example.com',
            [transfer.receiver.email],
            fail_silently=False,
            html_message=mensaje_destinatario
        )

        return Response({"detail": "Transferencia confirmada exitosamente."}, status=status.HTTP_200_OK)
###################################################################################
###### TRANSFER VIEW
class TransferView(generics.CreateAPIView):
    serializer_class = TransferSerializer

###################################################################################
###### VERIFY CEDULA AND SEND CODE
from django.utils import timezone
from datetime import timedelta
import random

class VerifyCedulaAndSendCodeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = CedulaVerificationSerializer(data=request.data)
        if serializer.is_valid():
            cedula = serializer.validated_data.get('cedula')
            user = User.objects.filter(cedula=cedula).first()
            
            if user:
                verification_code = f'{random.randint(100000, 999999)}'
                user.verification_code = verification_code
                user.verification_code_expiry = timezone.now() + timedelta(minutes=10)
                user.save()
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
                            .footer {{
                                margin-top: 20px;
                                font-size: 14px;
                                color: #777;
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h1>Código de Verificación</h1>
                            <p>Hola,</p>
                            <p>Para crear tu cuenta bancaria, utiliza el siguiente código de verificación:</p>
                            <h2>{verification_code}</h2>
                            <p>Este código es válido por 10 minutos. Si no has solicitado este cambio, puedes ignorar este correo.</p>
                            <div class="footer">
                                <p>Gracias,</p>
                                <p>El equipo de Banco Politécnico</p>
                            </div>
                        </div>
                    </body>
                </html>
                """
                subject = 'Código de Verificación para Crear Cuenta Bancaria'
                send_mail(subject, '', settings.DEFAULT_FROM_EMAIL, [user.email], html_message=html_message)
                
                return Response({'detail': 'Verification code sent to the user.'}, status=status.HTTP_200_OK)
            else:
                return Response({'detail': 'Cedula not found.'}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def verify_code_and_create_account(self, request, *args, **kwargs):
        verification_code = request.data.get('verification_code')
        user = User.objects.filter(verification_code=verification_code, verification_code_expiry__gte=timezone.now()).first()
        
        if user:
            serializer = BankAccountSerializer(data={'user': user.id, 'balance': 100.00})
            if serializer.is_valid():
                bank_account = serializer.save()
                subject = 'Cuenta Bancaria Creada'
                message = f'Se ha creado tu cuenta bancaria con éxito. Tu número de cuenta es: {bank_account.account_number}.'
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
                
                user.verification_code = None
                user.verification_code_expiry = None
                user.save()
                
                return Response({'detail': 'Bank account created successfully.'}, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'detail': 'Invalid or expired verification code.'}, status=status.HTTP_400_BAD_REQUEST)
        
###################################################################################
######  VERIFY CODE AND CREATE ACCOUNT
class VerifyCodeAndCreateAccountView(APIView):
    def post(self, request, *args, **kwargs):
        verification_code = request.data.get('verification_code')
        user = User.objects.filter(verification_code=verification_code, verification_code_expiry__gte=timezone.now()).first()
        
        if user:
            # Pasar el contexto del request al serializador
            serializer = BankAccountSerializer(data={'user': user.id, 'balance': 100.00}, context={'request': request})
            if serializer.is_valid():
                bank_account = serializer.save()
                subject = 'Cuenta Bancaria Creada'
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
                            .footer {{
                                margin-top: 20px;
                                font-size: 14px;
                                color: #777;
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h1>¡Cuenta Bancaria Creada!</h1>
                            <p>Hola,</p>
                            <p>Tu cuenta bancaria ha sido creada con éxito.</p>
                            <p><strong>Número de cuenta:</strong> {bank_account.account_number}</p>
                            <p>Gracias por elegir Banco Politécnico. Si tienes alguna pregunta, no dudes en ponerte en contacto con nosotros.</p>
                            <div class="footer">
                                <p>Atentamente,</p>
                                <p>El equipo de Banco Politécnico</p>
                            </div>
                        </div>
                    </body>
                </html>
                """
                subject = 'Tu Nueva Cuenta Bancaria en Banco Politécnico'
                send_mail(subject, '', settings.DEFAULT_FROM_EMAIL, [user.email], html_message=html_message)
                
                # Limpiar el código de verificación del usuario
                user.verification_code = None
                user.verification_code_expiry = None
                user.save()
                
                return Response({"detail": "Bank account created successfully and email sent."}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({'detail': 'Invalid or expired verification code.'}, status=status.HTTP_400_BAD_REQUEST)