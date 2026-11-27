# Secure Django Authentication

An educational Django authentication project demonstrating secure defaults with Django's built-in authentication system and django-axes login-attempt protection.

## Features

- User registration using Django's built-in password validators and password hashing.
- Login and logout using Django's authentication views.
- Authenticated dashboard protected by `login_required`.
- CSRF middleware and template tokens.
- Brute-force mitigation with django-axes (configurable failed-login limit and cool-off period).
- Environment-based secret key, allowed hosts, and production security settings.
- Automated tests for registration, login, logout, and access control.

## Requirements

- Python 3.10+
- Django 5.2
- django-axes 7+

## Run locally

```bash
cd projects/secure-django-auth
python -m venv .venv
# Windows: .venv\\Scripts\\activate
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

The example environment file is documentation for variables; Django reads actual environment variables from the shell. Set a development key before running:

```bash
export DJANGO_SECRET_KEY='replace-with-a-long-random-development-secret'
export DJANGO_DEBUG='True'
export DJANGO_ALLOWED_HOSTS='127.0.0.1,localhost'
python manage.py migrate
python manage.py runserver
```

Open http://127.0.0.1:8000/accounts/signup/ to register.

Run tests:

```bash
python manage.py test
```

## Security notes

- Passwords are never stored in plaintext; Django's password hashers handle storage.
- django-axes tracks repeated failed authentication attempts. The defaults in this demo lock out a username/IP combination after five failures for one hour.
- CSRF protection is enabled by Django middleware and template tokens.
- This is a learning project, not a production-ready identity provider.

## Before production

1. Set a unique, high-entropy `DJANGO_SECRET_KEY` outside source control.
2. Set `DJANGO_DEBUG=False` and configure exact `DJANGO_ALLOWED_HOSTS`.
3. Serve only over HTTPS; enable secure cookies and HSTS in the environment.
4. Use a production database, backups, monitoring, and dependency updates.
5. Review django-axes lockout settings for your threat model; consider reverse-proxy IP handling and account recovery flows.
6. Run `python manage.py check --deploy` against production settings.
7. Add email verification, password reset, MFA, and audit logging before using real accounts.

## Scope and limitations

This project demonstrates baseline web authentication controls. It does not implement MFA, email verification, password reset, social login, or a complete account-recovery process. Do not deploy it for real users without a security review.

## License

MIT
