import uuid 
from django.db import models
from django.contrib.auth import get_user_model
from django.conf import settings

User = get_user_model()

class Cuenta(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    account_number = models.CharField(max_length=20)
    account_number = models.CharField(max_length=50)  # Ajusta según tus necesidades
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=100.00)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.account_number} - {self.user.username}"

class Transferencia(models.Model):
    from_account = models.ForeignKey(Cuenta, related_name='transferencias_origen', on_delete=models.CASCADE)
    to_account = models.ForeignKey(Cuenta, related_name='transferencias_destino', on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    transaction_date = models.DateTimeField(auto_now_add=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.from_account} -> {self.to_account} : ${self.amount}"

class Service(models.Model):
    name = models.CharField(max_length=100)
    service_code = models.CharField(max_length=20, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class ServicePayment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    payment_code = models.CharField(max_length=20)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_date = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Audit(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=50)
    action_details = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
