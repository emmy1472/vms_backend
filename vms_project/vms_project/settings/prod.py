# myproject/settings/prod.py

from .base import *
import dj_database_url # type: ignore

DEBUG = False

ALLOWED_HOSTS = [ "localhost:5174", 'vms-backend-b84r.onrender.com']


SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# Example for PostgreSQL DB
DATABASES = {
    'default': dj_database_url.config(default='postgresql://vms_kv38_user:y7nVHrF2A7J21GZjkgs1Hbm9sLeaSlcu@dpg-d1dpn5re5dus73dqsimg-a/vms_kv38')
}

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.sendgrid.net'  # or any other provider
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL")


