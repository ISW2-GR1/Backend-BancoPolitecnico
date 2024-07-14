from django.contrib import admin
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.admin import TokenAdmin

# Obtén el modelo de usuario personalizado
User = get_user_model()

# Define un admin básico para el modelo User
class UserAdmin(admin.ModelAdmin):
    search_fields = ('username', 'email')  # Asegúrate de definir los campos de búsqueda

admin.site.register(User, UserAdmin)

class CustomTokenAdmin(TokenAdmin):
    search_fields = ('user__username', 'user__email')  # Define los campos para la búsqueda

try:
    admin.site.unregister(Token)
except admin.sites.NotRegistered:
    pass

admin.site.register(Token, CustomTokenAdmin)