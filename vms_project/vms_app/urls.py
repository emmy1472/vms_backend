from django.urls import path, include
from rest_framework.routers import DefaultRouter # type: ignore
from .views import (
    EmployeeViewSet, EmployeeProfileViewSet, DeviceViewSet, GuestViewSet, AccessLogViewSet,
    CustomTokenObtainPairView, MessageViewSet,
    AdminOverviewAPIView, AdminUsersAPIView, AdminEmployeesAPIView, AdminDevicesAPIView,
    AdminGuestsAPIView, AdminMessagesAPIView, AdminAccessLogsAPIView,
    user_me,
)
from rest_framework_simplejwt.views import TokenRefreshView # type: ignore
from .views import SecurityDeviceViewSet, SecurityAccessLogViewSet, SecurityDashboardAPIView, SecurityScanAPIView

router = DefaultRouter()
router.register(r'employees', EmployeeViewSet, basename='employee')
router.register(r'employee-profiles', EmployeeProfileViewSet, basename='employeeprofile')
router.register(r'devices', DeviceViewSet, basename='device')
router.register(r'guests', GuestViewSet, basename='guest')
router.register(r'messages', MessageViewSet, basename='message')
router.register(r'access-logs', AccessLogViewSet, basename='accesslog')
router.register(r'security/devices', SecurityDeviceViewSet, basename='security-devices')
router.register(r'security/access-logs', SecurityAccessLogViewSet, basename='security-access-logs')

urlpatterns = [
    # JWT Auth
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),  # login
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), # token refresh

    # Admin API endpoints
    path('admin/overview/', AdminOverviewAPIView.as_view(), name='admin-overview'),
    path('admin/users/', AdminUsersAPIView.as_view(), name='admin-users'),
    path('admin/employees/', AdminEmployeesAPIView.as_view(), name='admin-employees'),
    path('admin/devices/', AdminDevicesAPIView.as_view(), name='admin-devices'),
    path('admin/guests/', AdminGuestsAPIView.as_view(), name='admin-guests'),
    path('admin/messages/', AdminMessagesAPIView.as_view(), name='admin-messages'),
    path('admin/access-logs/', AdminAccessLogsAPIView.as_view(), name='admin-access-logs'),

    # User API endpoint (add 'api/' prefix to match frontend requests)
    path('users/me/', user_me, name='user-me'),

    # DRF router endpoints
    path('', include(router.urls)),

    # Security dashboard endpoint
    path('security/dashboard/', SecurityDashboardAPIView.as_view(), name='security-dashboard'),

    # Security scan endpoint
    path('security/scan/', SecurityScanAPIView.as_view(), name='security-scan'),
]

# No changes needed. The @action methods you added to your ViewSets are automatically routed by DRF's DefaultRouter.
# You can access them at:
#   /employee-profiles/scan-qr/
#   /devices/scan-qr/
#   /guests/scan-qr/
