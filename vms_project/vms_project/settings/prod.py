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



