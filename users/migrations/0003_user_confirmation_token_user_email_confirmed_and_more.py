# Generated by Django 5.0.3 on 2024-07-22 03:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_alter_user_address_alter_user_cedula_alter_user_city_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='confirmation_token',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='email_confirmed',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='reset_password_expires',
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='reset_password_token',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
