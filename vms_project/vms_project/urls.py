"""
URL configuration for vms_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_yasg.views import get_schema_view  # type: ignore
from drf_yasg import openapi  # type: ignore

schema_view = get_schema_view(
   openapi.Info(
      title="VMS API",
      default_version='v1',
      description="API documentation for the VMS project",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@vms.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
)

urlpatterns = [
    path('ams_netco/', admin.site.urls),
    path('api/', include('vms_app.urls')),
    path('api/', include('employee.urls')),
    path('api/', include('device.urls')),
    path('api/', include('access_log.urls')),
    path('api/', include('message.urls')),
    path('api/', include('guest.urls')),
    path('api/api.json/', schema_view.without_ui(cache_timeout=0),
         name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc',cache_timeout=0),
         name='schema-redoc'),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)