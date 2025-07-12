# myproject/settings/prod.py

from .base import *
import dj_database_url # type: ignore

DEBUG = False

ALLOWED_HOSTS = [ "localhost:5174", 'vms-backend-b84r.onrender.com']


SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True




