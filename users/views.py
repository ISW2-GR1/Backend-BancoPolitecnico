from rest_framework import generics, authentication, permissions
from rest_framework.authtoken.views import ObtainAuthToken
from users.serializers import UserSerializer, AuthTokenSerializer
from users.models import User
from rest_framework.response import Response
from rest_framework.views import APIView


# CREATE USER
class CreateUserView(generics.CreateAPIView):
    serializer_class = UserSerializer

# VIEW USERS
class ListUserView(generics.ListAPIView):
    serializer_class = UserSerializer
    queryset = User.objects.all()

#VIEW AND UPDATE USERS    
class RetreiveUpdateUserView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        return self.request.user

# CREATE TOKEN
class CreateTokenView(ObtainAuthToken):
    serializer_class = AuthTokenSerializer

# LOGOUT
class LogoutView(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        request.user.auth_token.delete()
        return Response(status=204)