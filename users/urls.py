from django.urls import path,include
from users import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path("register/", views.CreateUserView.as_view(), name="register"),
    path('login/', views.CreateTokenView.as_view(), name='create_token'),
    path("verify-login-code/", views.VerifyLoginCodeView.as_view(), name="verify_login_code"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("profile/", views.RetrieveUpdateUserView.as_view(), name="profile"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("password-reset/", views.PasswordResetView.as_view(), name="password_reset"),
    path("password-reset-confirm/", views.PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
    path("email-confirm/", views.EmailConfirmationView.as_view(), name="email_confirm"),
    path("verify-cedula/", views.CedulaVerificationView.as_view(), name="verify_cedula"),
    path('transfer-money/', views.TransferView.as_view(), name='transfer_money'),
    path('confirm-transfer/', views.ConfirmTransferView.as_view(), name='confirm_transfer'),
    
    path('update-username/', views.UpdateUsernameView.as_view(), name='update_username'),
    path('update-password/', views.UpdatePasswordView.as_view(), name='update_password'),

    
    #Routes of create account with cedula verification
    path('verify-cedula-and-send-code/', views.VerifyCedulaAndSendCodeView.as_view(), name='verify_cedula_and_send_code'),
    path('verify-code-and-create-account/', views.VerifyCodeAndCreateAccountView.as_view(), name='verify_code_and_create_account'),
    
    path('user/bank-accounts/', views.UserBankAccountsListView.as_view(), name='user-bank-accounts'),
    path('search/bank-accounts/', views.BankAccountSearchView.as_view(), name='search-bank-accounts'),
    
    
    path('request-deactivation/', views.RequestAccountDeactivationView.as_view(), name='request-account-deactivation'),
    path('confirm-deactivation/', views.ConfirmAccountDeactivationView.as_view(), name='confirm-account-deactivation'),
    
    path('transfer-summary/', views.TransferSummaryView.as_view(), name='transfer-summary'),
    
    
    path('contacts/add/', views.AddContactView.as_view(), name='add_contact'),
    path('contacts/deactivate/<int:contact_id>/', views.DeactivateContactView.as_view(), name='deactivate_contact'),
    path('contacts/', views.ContactListView.as_view(), name='contact_list'),

]
