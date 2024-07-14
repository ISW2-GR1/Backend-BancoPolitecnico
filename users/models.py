from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser, 
    PermissionsMixin, 
    BaseUserManager
)

#VALIDACIÓN CORREO

class UserManager(BaseUserManager):
    
    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('You must provide an email address or password to create a new user from an existing user.')
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        #Generar token de confirmación
        # token_confirmado = secrets.token_hex(16)

        #Enviar al correo
        # subject = 'Email Confirmation'
        # message = f'Please use this link to confirm your email: http://your-website.com/confirm/{confirmation_token}/'
        # from_email = email  # Use the user's email as the sender
        
        # send_mail(subject, message, from_email, [email])
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
    username = models.CharField(max_length=50)
    birthday = models.DateField(null=True)
    email = models.EmailField(max_length=150, unique=True, blank=False)
    password = models.CharField(max_length=150)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()
    
    USERNAME_FIELD ='email'
