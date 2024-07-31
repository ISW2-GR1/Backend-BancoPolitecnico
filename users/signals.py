from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User, BankAccount
import random
import string

@receiver(post_save, sender=User)
def create_bank_account(sender, instance, created, **kwargs):
    if created and instance.role == '2':
        account_number = generate_unique_account_number()
        BankAccount.objects.create(user=instance, account_number=account_number)

def generate_unique_account_number():
    while True:
        account_number = ''.join(random.choices(string.digits, k=10))
        if not BankAccount.objects.filter(account_number=account_number).exists():
            return account_number