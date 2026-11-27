from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView
from django.shortcuts import redirect, render

from .forms import SignUpForm


def signup(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("login")
    else:
        form = SignUpForm()

    return render(request, "registration/signup.html", {"form": form})


class SecureLoginView(LoginView):
    template_name = "registration/login.html"
    redirect_authenticated_user = True


class SecureLogoutView(LogoutView):
    # Django's LogoutView accepts POST requests to prevent logout CSRF.
    http_method_names = ["post", "options"]


@login_required
def dashboard(request):
    return render(request, "accounts/dashboard.html")
