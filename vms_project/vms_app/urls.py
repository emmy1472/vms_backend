from django.urls import path, include
from rest_framework.routers import DefaultRouter # type: ignore
from .views import EmployeeViewSet, EmployeeProfileViewSet, DeviceViewSet, GuestViewSet, AccessLogViewSet
from rest_framework_simplejwt.views import  TokenRefreshView # type: ignore
from .views import CustomTokenObtainPairView

router = DefaultRouter()
router.register(r'employees', EmployeeViewSet, basename='employee')
router.register(r'employee-profiles', EmployeeProfileViewSet, basename='employeeprofile')
router.register(r'devices', DeviceViewSet, basename='device')
router.register(r'guests', GuestViewSet, basename='guest')

router.register(r'access-logs', AccessLogViewSet, basename='accesslog')

urlpatterns = [
    # JWT Auth
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),  # login
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), # token refresh

    # API routes via router
    path('', include(router.urls)),
]

# No changes needed. The @action methods you added to your ViewSets are automatically routed by DRF's DefaultRouter.
# You can access them at:
#   /employee-profiles/scan-qr/
#   /devices/scan-qr/
#   /guests/scan-qr/
