from django.urls import path

from .views import LoginView, ProfileView

urlpatterns = [
    path('', LoginView.as_view()),
    path('profile', ProfileView.as_view()),
]
