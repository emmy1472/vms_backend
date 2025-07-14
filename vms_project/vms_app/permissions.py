from rest_framework.permissions import BasePermission, SAFE_METHODS # type: ignore

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'


class IsEmployee(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'employee'


class IsSecurity(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and getattr(request.user, "role", None) == "security"


class IsOwnerOrAdmin(BasePermission):
    """
    Allow access to the owner of the object or an admin.
    """
    def has_object_permission(self, request, view, obj):
        return obj.user == request.user or request.user.role == 'admin'


class IsEmployeeOrSecurityOrAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role in ["employee", "security", "admin"]
    

class IsAdminOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        # Admin can do anything, employee can only read
        if not request.user.is_authenticated:
            return False
        if getattr(request.user, "role", None) == "admin":
            return True
        if (
            request.method in ["GET", "HEAD", "OPTIONS"]
            and getattr(request.user, "role", None) == "employee"
        ):
            return True
        return False

class IsAdminOrEmployee(BasePermission):
    def has_permission(self, request, view):
        return hasattr(request.user, 'role') and request.user.role in ['admin', 'employee']
