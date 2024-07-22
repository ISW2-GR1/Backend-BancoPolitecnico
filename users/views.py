from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from users.serializers import UserSerializer, AuthTokenSerializer
from users.serializers import PasswordResetSerializer, PasswordResetConfirmSerializer,EmailConfirmationSerializer, CedulaVerificationSerializer, VerifyLoginCodeSerializer
from rest_framework.permissions import AllowAny
from rest_framework import generics
from .models import User
import secrets
from django.core.mail import send_mail
from rest_framework import status

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