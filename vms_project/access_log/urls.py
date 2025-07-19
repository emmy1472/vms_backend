from django.urls import path, include
from rest_framework.routers import DefaultRouter # type: ignore
from .views import AccessLogViewSet, SecurityAccessLogViewSet, AdminAccessLogsAPIView

router = DefaultRouter()
router.register(r"access-logs", AccessLogViewSet, basename="accesslog")


urlpatterns = [
    path("", include(router.urls)),
    path('security/access-logs/', SecurityAccessLogViewSet.as_view({'get': 'list'}), name='security-access-logs'),
    path('admin/access-logs/', AdminAccessLogsAPIView.as_view(), name='admin-access-logs'),
]