# Generated by Django 5.0.3 on 2024-08-10 09:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0012_bankaccount_is_primary'),
    ]

    operations = [
        migrations.AddField(
            model_name='transfer',
            name='receiver_account_number',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AddField(
            model_name='transfer',
            name='sender_account_number',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
    ]