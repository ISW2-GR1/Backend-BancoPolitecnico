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
    EmailConfirmationSerializer, CedulaVerificationSerializer, VerifyLoginCodeSerializer, ConfirmTransferSerializer, CedulaVerificationSerializerAccount
)
from .models import BankAccount, Transfer,Contact
from .signals import generate_unique_account_number
from .models import User

###################################################################################
##### CREATE USER
class CreateUserView(generics.CreateAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        user = serializer.save()

        # Crear la cuenta bancaria con un saldo inicial de 100 dólares
        BankAccount.objects.create(
            user=user,
            account_number=generate_unique_account_number(),
            balance=100.00,
            is_active=True,
            is_primary=True
        )
        
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
            return Response({'detail': 'Credenciales inválidas'}, status=status.HTTP_400_BAD_REQUEST)

        if not user.is_active:
            return Response({'detail': 'La cuenta está inactiva'}, status=status.HTTP_400_BAD_REQUEST)

        # Aquí puedes generar el token que necesites si estás usando JWT u otro sistema
        # Suponiendo que uses JWT
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # Enviar notificación al correo del usuario
        subject = 'Confirmación de Ingreso a Banca Web'
        message = f"""
        <html>
            <head>
                <style>
                    body {{
                        font-family: 'Arial', sans-serif;
                        background-color: #f4f4f4;
                        color: #333;
                        margin: 0;
                        padding: 20px;
                    }}
                    .container {{
                        max-width: 600px;
                        margin: auto;
                        background-color: #ffffff;
                        padding: 30px;
                        border-radius: 10px;
                        box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
                        border: 1px solid #e1e1e1;
                    }}
                    h1 {{
                        color: #0056b3;
                        font-size: 28px;
                        border-bottom: 2px solid #0056b3;
                        padding-bottom: 10px;
                        margin-bottom: 20px;
                    }}
                    p {{
                        font-size: 16px;
                        line-height: 1.6;
                        margin: 10px 0;
                    }}
                    .details {{
                        margin-top: 20px;
                        padding: 15px;
                        background-color: #f9f9f9;
                        border-radius: 5px;
                        border: 1px solid #ddd;
                    }}
                    .footer {{
                        margin-top: 30px;
                        font-size: 14px;
                        color: #555;
                        text-align: center;
                    }}
                    .footer a {{
                        color: #007BFF;
                        text-decoration: none;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Ingreso a Banca Web</h1>
                    <p>Hola {user.username},</p>
                    <p>Tu ingreso se realizó con éxito.</p>
                    <div class="details">
                        <p><strong>Detalle:</strong></p>
                        <p><strong>IP:</strong> {request.META.get('REMOTE_ADDR', 'Desconocida')}</p>
                        <p><strong>Ubicación:</strong> Ecuador</p>
                    </div>
                    <p>Si no has solicitado este servicio, por favor repórtalo a nuestra Banca Telefónica al (02)2999 999.</p>
                    <div class="footer">
                        <p>Gracias por utilizar nuestros servicios.</p>
                        <p>Atentamente,</p>
                        <p><strong>Banco Politécnico</strong></p>
                        <p><a href="https://www.banco-politecnico.online">www.banco-politecnico.online</a></p>
                    </div>
                </div>
            </body>
        </html>
        """

        email = EmailMessage(
            subject,
            message,
            'no-reply@example.com',
            [user.email]
        )
        email.content_subtype = 'html'
        email.send()

        return Response({
            'refresh': str(refresh),
            'access': access_token
        })
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
        serializer = CedulaVerificationSerializerAccount(data=request.data)
        if serializer.is_valid():
            cedula = serializer.validated_data.get('cedula')
            user = request.user

            # Verificar si la cédula pertenece al usuario autenticado
            if user.cedula == cedula:
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
                
                return Response({'detail': 'Código de verificación enviado al usuario.'}, status=status.HTTP_200_OK)
            else:
                return Response({'detail': 'La cédula no pertenece al usuario autenticado.'}, status=status.HTTP_400_BAD_REQUEST)
        
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
                
                return Response({'detail': 'Cuenta bancaria creada con éxito.'}, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'detail': 'Código de verificación inválido o expirado.'}, status=status.HTTP_400_BAD_REQUEST)
        
###################################################################################
######  VERIFY CODE AND CREATE ACCOUNT
class VerifyCodeAndCreateAccountView(APIView):
    def post(self, request, *args, **kwargs):
        verification_code = request.data.get('verification_code')
        user = User.objects.filter(
            verification_code=verification_code,
            verification_code_expiry__gte=timezone.now()
        ).first()
        
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
                
                return Response({"detail": "Cuenta bancaria creada con éxito y correo enviado."}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({'detail': 'Código de verificación inválido o expirado.'}, status=status.HTTP_400_BAD_REQUEST)
    
############################################################################################################
###### BANK ACCOUNT LIST VIEW
class UserBankAccountsListView(generics.ListAPIView):
    serializer_class = BankAccountSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        user = self.request.user
        return BankAccount.objects.filter(user=user)
    
############################################################################################################
###### BANK ACCOUNT SEARCH VIEW
from rest_framework.request import Request

class BankAccountSearchView(generics.ListAPIView):
    serializer_class = BankAccountSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request: Request, *args, **kwargs):
        # Extraer los parámetros del cuerpo de la solicitud
        account_number = request.data.get('account_number', None)
        cedula = request.data.get('cedula', None)

        queryset = BankAccount.objects.all()

        if account_number:
            queryset = queryset.filter(account_number=account_number)

        if cedula:
            try:
                user = User.objects.get(cedula=cedula)
                queryset = queryset.filter(user=user)
            except User.DoesNotExist:
                # Si no se encuentra el usuario, se retorna un error
                return Response(
                    {'error': 'No se encontró un usuario con la cédula proporcionada.'},
                    status=status.HTTP_404_NOT_FOUND
                )

        if not queryset.exists():
            # Si el queryset está vacío, se retorna un error
            return Response(
                {'error': 'No se encontró ninguna cuenta bancaria con los criterios proporcionados.'},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    
############################################################################################################
######  REQUEST ACCOUNT DEACTIVATION
from rest_framework import status, views
from django.core.mail import EmailMessage
from .models import User
class RequestAccountDeactivationView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user

        # Verifica que el usuario esté autenticado
        if not user.is_authenticated:
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

        # Verificar el número de cuenta proporcionado
        account_number = request.data.get('account_number')
        account = BankAccount.objects.filter(user=user, account_number=account_number).first()
        if not account:
            return Response({'error': 'Invalid account number'}, status=status.HTTP_400_BAD_REQUEST)

        # Verificar si la cuenta es la principal
        if account.is_primary:
            return Response({'error': 'Cannot deactivate the primary account'}, status=status.HTTP_400_BAD_REQUEST)

        # Generar el código de verificación
        verification_code = user.generate_verification_code()

        subject = 'Código de Verificación para Desactivar tu Cuenta'
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
                <h1>Código de Verificación para Desactivar tu Cuenta</h1>
                <p>Hola,</p>
                <p>Para desactivar tu cuenta, por favor utiliza el siguiente código de verificación:</p>
                <p><strong>{verification_code}</strong></p>
                <p>Este código expirará en 10 minutos.</p>
                <div class="footer">
                    <p>Gracias,</p>
                    <p>El equipo de Banco Politécnico</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        from_email = 'info.iso50001@inn-energy.net'
        email = EmailMessage(subject, message, from_email, [user.email])
        email.content_subtype = 'html'
        email.send()

        return Response({'message': 'Verification code sent'}, status=status.HTTP_200_OK)

############################################################################################################
######  CONFIRM ACCOUNT DEACTIVATION
from .serializers import DeactivateAccountRequestSerializer
class ConfirmAccountDeactivationView(views.APIView):
    permission_classes = [IsAuthenticated]  # Requiere autenticación

    def post(self, request, *args, **kwargs):
        serializer = DeactivateAccountRequestSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        # Si el serializer es válido, significa que el código de verificación y el número de cuenta son correctos
        user = request.user
        account_number = serializer.validated_data.get('account_number')
        account = BankAccount.objects.filter(user=user, account_number=account_number).first()

        if not account:
            return Response({'error': 'Account not found'}, status=status.HTTP_404_NOT_FOUND)

        if account.is_primary:
            return Response({'error': 'Cannot deactivate the primary account'}, status=status.HTTP_400_BAD_REQUEST)

        # Transferir saldo a la cuenta principal
        primary_account = BankAccount.objects.filter(user=user, is_primary=True).first()
        if primary_account:
            primary_account.balance += account.balance
            primary_account.save()

        # Desactivar la cuenta
        account.is_active = False
        account.save()

        return Response({"detail": "Your account has been deactivated."}, status=status.HTTP_200_OK)



############################################################################################################
### TRANSFER SUMMARY
from datetime import datetime

class TransferSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user

        # Obtener las cuentas del usuario autenticado
        user_accounts = BankAccount.objects.filter(user=user)
        user_account_numbers = user_accounts.values_list('account_number', flat=True)

        # Obtener las fechas de los parámetros de la solicitud
        start_date_str = request.query_params.get('startDate')
        end_date_str = request.query_params.get('endDate')

        # Convertir las fechas de string a objetos datetime
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else None
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None

        # Obtener transferencias enviadas y recibidas
        sent_transfers = Transfer.objects.filter(sender=user, sender__bankaccount__account_number__in=user_account_numbers)
        received_transfers = Transfer.objects.filter(receiver=user, receiver__bankaccount__account_number__in=user_account_numbers)

        # Aplicar filtros de fecha si están presentes
        if start_date:
            sent_transfers = sent_transfers.filter(timestamp__gte=start_date)
            received_transfers = received_transfers.filter(timestamp__gte=start_date)

        if end_date:
            sent_transfers = sent_transfers.filter(timestamp__lte=end_date)
            received_transfers = received_transfers.filter(timestamp__lte=end_date)

        # Mapear números de cuenta a las transferencias
        def map_transfer_data(transfers, transfer_type):
            transfer_list = []
            seen_transfers = set()

            for transfer in transfers:
                sender_account = transfer.sender.bankaccount_set.first()
                receiver_account = transfer.receiver.bankaccount_set.first()

                transfer_data = {
                    'amount': transfer.amount,
                    'timestamp': transfer.timestamp,
                    'receiver': transfer.receiver.username if transfer_type == 'sent' else transfer.sender.username,
                    'sender': transfer.sender.username if transfer_type == 'received' else None,
                    'receiver_account_number': receiver_account.account_number if receiver_account else None,
                    'sender_account_number': sender_account.account_number if sender_account else None,
                    'concept': transfer.concept,
                    'type': transfer_type
                }

                transfer_id = (transfer_data['timestamp'], transfer_data['amount'], transfer_data['receiver'], transfer_data['sender'])
                if transfer_id not in seen_transfers:
                    seen_transfers.add(transfer_id)
                    transfer_list.append(transfer_data)

            return transfer_list

        sent_data = map_transfer_data(sent_transfers, 'sent')
        received_data = map_transfer_data(received_transfers, 'received')

        # Unir y ordenar las transferencias por fecha
        all_transfers = sorted(sent_data + received_data, key=lambda x: x['timestamp'], reverse=True)

        return Response(all_transfers, status=status.HTTP_200_OK)
    
    
from .serializers import ContactSerializer


class AddContactView(APIView):
    def post(self, request, *args, **kwargs):
        contact_account_id = request.data.get('contact')  # ID de la cuenta bancaria
        contact_account_number = request.data.get('contact_account_number')
        
        if not contact_account_id or not contact_account_number:
            return Response({"error": "Ambos, el ID de la cuenta de contacto y el número de cuenta, son requeridos."},
                            status=status.HTTP_400_BAD_REQUEST)
        
        try:
            contact_bank_account = BankAccount.objects.get(id=contact_account_id)
        except BankAccount.DoesNotExist:
            return Response({"error": "No existe una cuenta bancaria con el ID proporcionado."},
                            status=status.HTTP_404_NOT_FOUND)

        contact_user = contact_bank_account.user  # Obtener el usuario dueño de la cuenta bancaria

        # Verificar si ya existe un contacto con el mismo número de cuenta
        existing_contact = Contact.objects.filter(
            owner=request.user,
            contact_account_number=contact_account_number
        ).first()

        if existing_contact:
            return Response({"error": "Este número de cuenta ya está registrado como contacto."},
                            status=status.HTTP_400_BAD_REQUEST)
        
        # Crear un nuevo contacto
        contact = Contact.objects.create(
            owner=request.user,
            contact=contact_user,
            contact_account_number=contact_account_number
        )

        return Response(ContactSerializer(contact).data, status=status.HTTP_201_CREATED)




class DeactivateContactView(APIView):
    def delete(self, request, contact_id, *args, **kwargs):
        try:
            contact = Contact.objects.get(id=contact_id, owner=request.user)
            contact.is_active = False
            contact.save()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Contact.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

class ContactListView(generics.ListAPIView):
    serializer_class = ContactSerializer

    def get_queryset(self):
        return Contact.objects.filter(owner=self.request.user, is_active=True)
    
    

from .serializers import UpdateUsernameSerializer

class UpdateUsernameView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UpdateUsernameSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        # Obtiene el usuario actual desde el request
        return self.request.user

    def update(self, request, *args, **kwargs):
        # Llama al método update del serializador
        return super().update(request, *args, **kwargs)


from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import update_session_auth_hash
from .serializers import UpdatePasswordSerializer

class UpdatePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UpdatePasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        user = request.user
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']

        # Verificar la contraseña antigua
        if not user.check_password(old_password):
            return Response({'error': 'La contraseña antigua es incorrecta.'}, status=status.HTTP_400_BAD_REQUEST)

        # Actualiza la contraseña del usuario
        user.set_password(new_password)
        user.save()

        # Actualiza la sesión del usuario
        update_session_auth_hash(request, user)

        return Response({'status': 'Contraseña actualizada'}, status=status.HTTP_200_OK)
