from django.urls import path
from users import views

urlpatterns = [
    #path("list/", views.ListUserView.as_view()),
    path("register/", views.CreateUserView.as_view()),
    path("token/", views.CreateTokenView.as_view()),
    path("user/", views.RetreiveUpdateUserView.as_view()),
]
