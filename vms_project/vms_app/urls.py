from django.urls import path, include
from rest_framework.routers import DefaultRouter # type: ignore
from .views import (
    CreateEmployeeUserView,
    CustomTokenObtainPairView, MessageViewSet,
    AdminOverviewAPIView, AdminUsersAPIView, 
    AdminMessagesAPIView,
    user_me,
)
from rest_framework_simplejwt.views import TokenRefreshView # type: ignore
from .views import  SecurityDashboardAPIView,  SecurityScanAPIView

from django.conf import settings
from django.conf.urls.static import static






router = DefaultRouter()
router.register(r'messages', MessageViewSet, basename='message')

urlpatterns = [
    # JWT Auth
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),  # login
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), # token refresh
    path('users/', CreateEmployeeUserView.as_view(), name='create-user'),

    # Admin API endpoints

    path('admin/overview/', AdminOverviewAPIView.as_view(), name='admin-overview'),
    path('admin/users/', AdminUsersAPIView.as_view(), name='admin-users'),
    path('admin/messages/', AdminMessagesAPIView.as_view(), name='admin-messages'),
    # User API endpoint (add 'api/' prefix to match frontend requests)
    path('users/me/', user_me, name='user-me'),
    # DRF router endpoints
    path('', include(router.urls)),
    # Security dashboard endpoint
    path('security/dashboard/', SecurityDashboardAPIView.as_view(), name='security-dashboard'),
    # Security scan endpoint
    path('security/scan/', SecurityScanAPIView.as_view(), name='security-scan'),
]


urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)