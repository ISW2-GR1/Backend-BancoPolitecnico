from django.urls import path
from . import views

urlpatterns = [
    path('accounts/', views.BankAccountListCreateView.as_view(), name='bank-account-list-create'),
    path('accounts/<int:pk>/', views.BankAccountDetailView.as_view(), name='bank-account-detail'),
    path('transactions/', views.TransactionListCreateView.as_view(), name='transaction-list-create'),
    path('services/', views.ServiceListCreateView.as_view(), name='service-list-create'),
    path('service-payments/', views.ServicePaymentListCreateView.as_view(), name='service-payment-list-create'),
    path('audits/', views.AuditListCreateView.as_view(), name='audit-list-create'),
]
