from django.contrib import admin
from .models import Cuenta, Transferencia, Service, ServicePayment, Audit

class CuentaAdmin(admin.ModelAdmin):
    list_display = ('account_number', 'user', 'balance')


class TransferenciaAdmin(admin.ModelAdmin):
    list_display = ('from_account', 'to_account', 'amount', 'transaction_date')

class ServiceAdmin(admin.ModelAdmin):
    list_display = ('name', 'service_code')

class ServicePaymentAdmin(admin.ModelAdmin):
    list_display = ('user', 'service', 'amount', 'payment_date')

class AuditAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'timestamp')

admin.site.register(Cuenta, CuentaAdmin)
admin.site.register(Transferencia, TransferenciaAdmin)
admin.site.register(Service, ServiceAdmin)
admin.site.register(ServicePayment, ServicePaymentAdmin)
admin.site.register(Audit, AuditAdmin)
