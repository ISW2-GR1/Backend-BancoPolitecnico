# Generated by Django 5.0.3 on 2024-08-10 08:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0011_transfer_document_number'),
    ]

    operations = [
        migrations.AddField(
            model_name='bankaccount',
            name='is_primary',
            field=models.BooleanField(default=False),
        ),
    ]