from rest_framework import generics, permissions
from rest_framework.exceptions import ValidationError
from .models import Cuenta, Transferencia, Service, ServicePayment, Audit
from .serializers import CuentaSerializer, TransactionSerializer, ServiceSerializer, ServicePaymentSerializer, AuditSerializer

class BankAccountListCreateView(generics.ListCreateAPIView):
    queryset = Cuenta.objects.all()
    serializer_class = CuentaSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class BankAccountDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Cuenta.objects.all()
    serializer_class = CuentaSerializer
    permission_classes = [permissions.IsAuthenticated]

class TransactionListCreateView(generics.ListCreateAPIView):
    queryset = Transferencia.objects.all()
    serializer_class = TransactionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        from_account = serializer.validated_data['from_account']
        to_account = serializer.validated_data['to_account']
        amount = serializer.validated_data['amount']

        if from_account.user != self.request.user:
            raise ValidationError("You can only transfer from your own accounts.")
        if from_account.balance < amount:
            raise ValidationError("Insufficient balance.")

        from_account.balance -= amount
        to_account.balance += amount

        from_account.save()
        to_account.save()

        serializer.save()

class ServiceListCreateView(generics.ListCreateAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [permissions.IsAuthenticated]

class ServicePaymentListCreateView(generics.ListCreateAPIView):
    queryset = ServicePayment.objects.all()
    serializer_class = ServicePaymentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        service = serializer.validated_data['service']
        amount = serializer.validated_data['amount']

        primary_account = Cuenta.objects.filter(user=user).first()
        if primary_account.balance < amount:
            raise ValidationError("Insufficient balance in primary account.")

        primary_account.balance -= amount
        primary_account.save()

        serializer.save(user=user)

class AuditListCreateView(generics.ListCreateAPIView):
    queryset = Audit.objects.all()
    serializer_class = AuditSerializer
    permission_classes = [permissions.IsAuthenticated]
