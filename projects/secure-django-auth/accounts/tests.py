from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse


class AuthenticationFlowTests(TestCase):
    def test_signup_creates_user_with_hashed_password(self):
        response = self.client.post(
            reverse("signup"),
            {"username": "alice", "password1": "StrongPassphrase!2026", "password2": "StrongPassphrase!2026"},
        )
        self.assertRedirects(response, reverse("login"))
        user = User.objects.get(username="alice")
        self.assertNotEqual(user.password, "StrongPassphrase!2026")
        self.assertTrue(user.check_password("StrongPassphrase!2026"))

    def test_dashboard_requires_authentication(self):
        response = self.client.get(reverse("dashboard"))
        self.assertRedirects(response, f"{reverse('login')}?next={reverse('dashboard')}")

    def test_user_can_login_and_access_dashboard(self):
        User.objects.create_user(username="bob", password="StrongPassphrase!2026")
        response = self.client.post(
            reverse("login"),
            {"username": "bob", "password": "StrongPassphrase!2026"},
        )
        self.assertRedirects(response, reverse("dashboard"))
        self.assertEqual(self.client.get(reverse("dashboard")).status_code, 200)

    def test_logout_is_post_only(self):
        user = User.objects.create_user(username="carol", password="StrongPassphrase!2026")
        self.client.force_login(user)
        self.assertEqual(self.client.get(reverse("logout")).status_code, 405)
        response = self.client.post(reverse("logout"))
        self.assertRedirects(response, reverse("login"))
