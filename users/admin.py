from django.contrib import admin
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.admin import TokenAdmin

User = get_user_model()

class UserAdmin(admin.ModelAdmin):
    search_fields = ('username', 'email')

admin.site.register(User, UserAdmin)

class CustomTokenAdmin(TokenAdmin):
    search_fields = ('user__username', 'user__email')

try:
    admin.site.unregister(Token)
except admin.sites.NotRegistered:
    pass

admin.site.register(Token, CustomTokenAdmin)