from django.urls import path, include
from rest_framework.routers import DefaultRouter  # Handles automatic routing for viewsets # type: ignore

# Import views
from .views import (
    AccessLogViewSet,
    SecurityAccessLogViewSet,
    AdminAccessLogsAPIView,
    SecurityScanAPIView
)

# Initialize DRF's default router
router = DefaultRouter()

# Register the main access log viewset (supports CRUD operations)
router.register(r"access-logs", AccessLogViewSet, basename="accesslog")

# Define all API routes for this app
urlpatterns = [
    # Include all automatically registered routes from the router (e.g. /access-logs/)
    path("", include(router.urls)),

    # Custom endpoint for Security personnel to fetch access logs (GET only)
    path('security/access-logs/', SecurityAccessLogViewSet.as_view({'get': 'list'}), name='security-access-logs'),

    # Admin-only endpoint to view all access logs (GET only)
    path('admin/access-logs/', AdminAccessLogsAPIView.as_view(), name='admin-access-logs'),

    # Endpoint for scanning QR/token/device during entry/exit
    path('security/scan/', SecurityScanAPIView.as_view(), name='security-scan'),
]
