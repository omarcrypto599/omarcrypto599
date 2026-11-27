from django.urls import path
from .views import SecureLoginView, SecureLogoutView, dashboard, signup

urlpatterns = [
    path("signup/", signup, name="signup"),
    path("login/", SecureLoginView.as_view(), name="login"),
    path("logout/", SecureLogoutView.as_view(), name="logout"),
    path("dashboard/", dashboard, name="dashboard"),
]
