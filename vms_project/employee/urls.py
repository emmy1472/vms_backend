from django.urls import path, include
from rest_framework.routers import DefaultRouter # type: ignore
from .views import  EmployeeProfileViewSet, EmployeeViewSet, AdminEmployeesAPIView

router = DefaultRouter()
router.register(r"employees", EmployeeViewSet, basename="employee")
router.register(r"employee-profiles", EmployeeProfileViewSet, basename="employee-profile")

urlpatterns = [
    path("", include(router.urls)),
    path('admin/employees/', AdminEmployeesAPIView.as_view(), name='admin-employees')
]
