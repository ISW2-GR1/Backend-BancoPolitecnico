from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers, generics, permissions, status, viewsets
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

# CREATE USER
class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    def perform_create(self, serializer):
        
        serializer.save()
# VIEW AND UPDATE USERS
class RetrieveUpdateUserView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        user = self.request.user

        # Prefetch related data for the user
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
    

# CREATE TOKEN
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

# LOGOUT
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response(status=status.HTTP_204_NO_CONTENT)

class PasswordResetView(generics.CreateAPIView):
    serializer_class = PasswordResetSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password reset email sent.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmailConfirmationView(generics.GenericAPIView):
    serializer_class = EmailConfirmationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"detail": "Email confirmed successfully."})

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

class CedulaVerificationView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = CedulaVerificationSerializer(data=request.data)
        if serializer.is_valid():
            return Response({"message": "Cedula is valid."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class BankAccountViewSet(viewsets.ModelViewSet):
    queryset = BankAccount.objects.all()
    serializer_class = BankAccountSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return BankAccount.objects.filter(user=self.request.user)

class CreateBankAccountView(generics.CreateAPIView):
    serializer_class = BankAccountSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        account_number = generate_unique_account_number()
        bank_account = serializer.save(user=self.request.user, account_number=account_number)
        self.send_account_creation_email(bank_account)

    def send_account_creation_email(self, bank_account):
        subject = 'Your New Bank Account'
        message = f'Your new bank account has been created. Your account number is {bank_account.account_number}.'
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [bank_account.user.email])



class TransferMoneyView(APIView):
    serializer_class = TransferSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            sender_account_number = serializer.validated_data.get('sender_account')
            receiver_account_number = serializer.validated_data.get('receiver_account')
            amount = serializer.validated_data.get('amount')
            user = request.user

            try:
                # Obtén la cuenta del remitente
                sender_account = BankAccount.objects.get(account_number=sender_account_number, user=user)
            except BankAccount.DoesNotExist:
                return Response({"detail": "Sender account not found or unauthorized."}, status=status.HTTP_400_BAD_REQUEST)

            try:
                # Obtén la cuenta del destinatario
                receiver_account = BankAccount.objects.get(account_number=receiver_account_number)
            except BankAccount.DoesNotExist:
                return Response({"detail": "Receiver account does not exist."}, status=status.HTTP_400_BAD_REQUEST)

            if sender_account.balance < amount:
                return Response({"detail": "Insufficient funds."}, status=status.HTTP_400_BAD_REQUEST)

            # Realiza la transferencia dentro de una transacción atómica
            with transaction.atomic():
                sender_account.balance -= amount
                receiver_account.balance += amount

                sender_account.save()
                receiver_account.save()

                # Guarda el registro de la transferencia
                serializer.save()

                # Envía un correo al destinatario de la transferencia
                self.send_transfer_notification(receiver_account.user.email, amount, sender_account_number)

                return Response({'detail': 'Transfer initiated successfully.'}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_transfer_notification(self, recipient_email, amount, sender_account_number):
        subject = 'Transfer Received'
        message = f'You have received a transfer of {amount} from account number {sender_account_number}.'
        from_email = 'no-reply@example.com'
        send_mail(subject, message, from_email, [recipient_email])
        

class ConfirmTransferView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = ConfirmTransferSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        transfer = serializer.save()

        # Notify the receiver
        send_mail(
            'Transfer Received',
            f'You have received a transfer of {transfer.amount} from {transfer.sender.username}.',
            'no-reply@example.com',
            [transfer.receiver.email]
        )

        return Response({"detail": "Transfer confirmed successfully."}, status=status.HTTP_200_OK)


class TransferView(generics.CreateAPIView):
    serializer_class = TransferSerializer