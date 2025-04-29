# permissions.py
from rest_framework.permissions import BasePermission

class IsManager(BasePermission):
    """
    Custom permission to only allow managers to access the view.
    Checks multiple possible ways manager status might be defined.
    """
    def has_permission(self, request, view):
        user = request.user
        return any([
            user.groups.filter(name='Managers').exists(),
            user.groups.filter(name__iexact='manager').exists(),
            getattr(user, 'is_manager', False),
            user.is_staff,
            user.is_superuser
        ])
        

        