from django.urls import path
from users import views

urlpatterns = [
    #path("list/", views.ListUserView.as_view()),
    path("register/", views.CreateUserView.as_view()),
    path("login/", views.CreateTokenView.as_view()),
    path("profile/", views.RetreiveUpdateUserView.as_view()),
    path("logout/", views.LogoutView.as_view()),
]
