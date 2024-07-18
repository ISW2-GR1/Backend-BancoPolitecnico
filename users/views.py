from rest_framework import generics, authentication, permissions
from rest_framework.authtoken.views import ObtainAuthToken
from users.serializers import UserSerializer, AuthTokenSerializer
from users.models import User
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token


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

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key})

# LOGOUT
class LogoutView(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        request.user.auth_token.delete()
        return Response(status=204)