from django.urls import path,include
from users import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path("register/", views.CreateUserView.as_view(), name="register"),
    path("login/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("verify-login-code/", views.VerifyLoginCodeView.as_view(), name="verify_login_code"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("profile/", views.RetrieveUpdateUserView.as_view(), name="profile"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("password-reset/", views.PasswordResetView.as_view(), name="password_reset"),
    path("password-reset-confirm/", views.PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
    path("email-confirm/", views.EmailConfirmationView.as_view(), name="email_confirm"),
    path("verify-cedula/", views.CedulaVerificationView.as_view(), name="verify_cedula"),
    path("create-bank-account/", views.CreateBankAccountView.as_view(), name="create_bank_account"),
    path('transfer-money/', views.TransferView.as_view(), name='transfer_money'),
    path('confirm-transfer/', views.ConfirmTransferView.as_view(), name='confirm_transfer'),
]
