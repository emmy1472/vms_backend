from django.urls import path, include
from rest_framework.routers import DefaultRouter # type: ignore
from .views import  EmployeeProfileViewSet, DeviceViewSet, GuestViewSet, GuestDeviceViewSet, AccessLogViewSet
from rest_framework_simplejwt.views import  TokenRefreshView # type: ignore
from .views import CustomTokenObtainPairView

router = DefaultRouter()
router.register(r'employee-profiles', EmployeeProfileViewSet, basename='employeeprofile')
router.register(r'devices', DeviceViewSet, basename='device')
router.register(r'guests', GuestViewSet, basename='guest')
router.register(r'guest-devices', GuestDeviceViewSet, basename='guestdevice')
router.register(r'access-logs', AccessLogViewSet, basename='accesslog')

urlpatterns = [
    # JWT Auth
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),  # login
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), # token refresh

    # API routes via router
    path('', include(router.urls)),
]
