from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from users.serializers import UserSerializer, AuthTokenSerializer, BankAccountSerializer
from users.serializers import PasswordResetSerializer, PasswordResetConfirmSerializer,EmailConfirmationSerializer, CedulaVerificationSerializer, VerifyLoginCodeSerializer
from rest_framework.permissions import AllowAny
from rest_framework import generics
from .models import User
import secrets
from django.core.mail import send_mail
from rest_framework import status, viewsets
from django.db import transaction
from .models import BankAccount
from rest_framework.permissions import IsAuthenticated
from django.conf import settings
from .signals import generate_unique_account_number

# CREATE USER
class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    def perform_create(self, serializer):
        
        serializer.save()

# VIEW AND UPDATE USERS    
class RetreiveUpdateUserView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        return self.request.user

# CREATE TOKEN
class CreateTokenView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(request=request, username=email, password=password)
        if not user:
            return Response({'detail': 'Invalid credentials'}, status=400)

        if not user.is_active:
            return Response({'detail': 'Account is inactive'}, status=400)

        # Generate a new verification code
        verification_code = secrets.token_hex(6)  # Generates a 12-character code
        user.verification_code = verification_code
        user.save()

        # Send verification code to email
        subject = 'Your Login Verification Code'
        message = f'Your new verification code is: {verification_code}'
        from_email = 'no-reply@example.com'
        send_mail(subject, message, from_email, [user.email])

        return Response({"detail": "Verification code sent to your email."})

# LOGOUT
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        refresh_token = request.data.get("refresh")
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response(status=204)

class PasswordResetView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()  # Esto llamará al método `save()` del serializer
            return Response({'message': 'Password reset email sent.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class PasswordResetConfirmView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()  # Esto llamará al método `save()` del serializer
            return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailConfirmationView(generics.GenericAPIView):
    serializer_class = EmailConfirmationSerializer
    permission_classes = [AllowAny]

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
            return Response({"detail": "Invalid verification code"}, status=400)

        # Clear the verification code
        user.verification_code = None
        user.save()

        # Generate tokens
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
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return BankAccount.objects.filter(user=user)

class TransferMoneyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        from_account_number = request.data.get('from_account_number')
        to_account_number = request.data.get('to_account_number')
        amount = request.data.get('amount')

        try:
            amount = float(amount)
        except ValueError:
            return Response({'error': 'Invalid amount.'}, status=status.HTTP_400_BAD_REQUEST)

        if amount <= 0:
            return Response({'error': 'Amount must be positive.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            from_account = BankAccount.objects.get(user=request.user, account_number=from_account_number)
            to_account = BankAccount.objects.get(account_number=to_account_number)
        except BankAccount.DoesNotExist:
            return Response({'error': 'Account not found.'}, status=status.HTTP_404_NOT_FOUND)

        if from_account.balance < amount:
            return Response({'error': 'Insufficient funds.'}, status=status.HTTP_400_BAD_REQUEST)

        from_account.balance -= amount
        to_account.balance += amount

        from_account.save()
        to_account.save()

        self.send_transfer_email(from_account.user.email, to_account_number, amount)
        self.send_transfer_email(to_account.user.email, from_account_number, amount)

        return Response({'success': 'Transfer completed successfully.'}, status=status.HTTP_200_OK)

    def send_transfer_email(self, recipient_email, account_number, amount):
        subject = 'Bank Account Transfer Notification'
        message = f'You have received a transfer of ${amount:.2f} to/from account {account_number}.'
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [recipient_email])


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
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [bank_account.user.email]
        send_mail(subject, message, from_email, recipient_list)