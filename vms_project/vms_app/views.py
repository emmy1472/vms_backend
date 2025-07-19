from asyncio.log import logger
from datetime import datetime
import logging
from smtplib import SMTPException
from rest_framework import viewsets, generics # type: ignore  # View classes for API endpoints
from rest_framework.response import Response # type: ignore # Used to return API responses
from rest_framework.decorators import api_view, permission_classes # type: ignore  # Function-based view tools
from rest_framework.permissions import IsAuthenticated # type: ignore # Permission to require login
from rest_framework.views import APIView # type: ignore # Base class for API Views
from rest_framework_simplejwt.views import TokenObtainPairView # type: ignore # JWT Token View
from django.contrib.auth import get_user_model  # To get the custom user model
from django.core.exceptions import ValidationError  # To raise validation errors
from django.core.mail import BadHeaderError, EmailMessage  # Email utilities
from django.conf import settings  # Django settings access
from django.template.loader import render_to_string  # For rendering HTML email templates
from django.utils.html import strip_tags  # To strip HTML for plain message

# Import serializers
from .serializers import CustomTokenObtainPairSerializer
from employee.serializers import RegisterEmployeeSerializer

# Import models
from message.models import Message
from .permissions import IsAdmin, IsSecurity
from guest.models import Guest
from employee.models import EmployeeProfile
from device.models import Device
from access_log.models import AccessLog

# Initialize logger
logger = logging.getLogger(__name__)

# Custom JWT token view to include role in response
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

# Set user model
User = get_user_model()

# API for admin to create employee user accounts
class CreateEmployeeUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterEmployeeSerializer
    permission_classes = [IsAuthenticated]  # Add IsAdmin if needed

    def perform_create(self, serializer):
        # Save the new user with default password
        user = serializer.save(password="Welcome$")

        try:
            logo_url = settings.APP_LOGO_URL
            html_message = render_to_string("welcome_email.html", {
                "username": user.username,
                "app_name": "NETCO Visitor Management System",
                "logo_url": logo_url,
                "default_password": "Welcome$",
            })
            plain_message = strip_tags(html_message)

            email = EmailMessage(
                subject="Welcome to NETCO Visitor Management System",
                body=html_message,
                from_email=f'"NETCO Visitor Management System" <{settings.DEFAULT_FROM_EMAIL}>',
                to=[user.email],
            )
            email.content_subtype = "html"
            sent_count = email.send(fail_silently=False)

        except BadHeaderError:
            raise ValidationError({"detail": "Invalid header found while sending email."})
        except SMTPException as e:
            raise ValidationError({"detail": f"SMTP error occurred: {str(e)}"})
        except Exception as e:
            raise ValidationError({"detail": f"Unexpected error sending email: {str(e)}"})

    def get_queryset(self):
        return User.objects.filter(role="employee")



# Admin dashboard overview metrics
class AdminOverviewAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        return Response({
            "users": User.objects.count(),
            "employees": EmployeeProfile.objects.count(),
            "devices": Device.objects.count(),
            "guests": Guest.objects.count(),
            "messages": Message.objects.count(),
            "access_logs": AccessLog.objects.count(),
        })

# Admin table for users
class AdminUsersAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        users = User.objects.all().values("id", "username", "email", "role", "is_active")
        return Response(list(users))



# Returns currently authenticated user info
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_me(request):
    user = request.user
    return Response({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": getattr(user, "role", None),
    })

# Security dashboard metrics for today
class SecurityDashboardAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSecurity]

    def get(self, request):
        device_count = Device.objects.count()
        verified_device_count = Device.objects.filter(is_verified=True).count()
        guest_count = Guest.objects.count()
        guests_today = Guest.objects.filter(visit_date=datetime.now().date()).count()
        expected_guests_today = Guest.objects.filter(
            visit_date=datetime.now().date(), token_expiry__gte=datetime.now()
        ).count()
        access_logs_today = AccessLog.objects.filter(time_in__date=datetime.now().date()).count()

        return Response({
            "device_count": device_count,
            "verified_device_count": verified_device_count,
            "guest_count": guest_count,
            "guests_today": guests_today,
            "expected_guests_today": expected_guests_today,
            "access_logs_today": access_logs_today,
        })


