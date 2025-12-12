from django.shortcuts import redirect
from django.urls import reverse
from logs.models import SecurityLog

class SecurityLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        return response
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        # Log access to protected views
        if request.user.is_authenticated and hasattr(view_func, '__name__'):
            view_name = view_func.__name__
            if any(keyword in view_name.lower() for keyword in ['upload', 'download', 'delete', 'share']):
                SecurityLog.objects.create(
                    user=request.user,
                    action='VIEW_ACCESS',
                    description=f'Accessed {view_name}',
                    ip_address=self.get_client_ip(request)
                )
        
        # Check role-based access
        if request.user.is_authenticated:
            user_role = request.user.role
            path = request.path
            
            # Admin-only areas
            if path.startswith('/admin/') and user_role != 'admin':
                SecurityLog.objects.create(
                    user=request.user,
                    action='UNAUTHORIZED_ACCESS',
                    description=f'Attempted to access admin area: {path}',
                    ip_address=self.get_client_ip(request)
                )
                return redirect('dashboard')
            
            # User-only areas (exclude guests)
            if user_role == 'guest' and any(keyword in path for keyword in ['/upload/', '/share/']):
                SecurityLog.objects.create(
                    user=request.user,
                    action='UNAUTHORIZED_ACCESS',
                    description=f'Guest attempted restricted action: {path}',
                    ip_address=self.get_client_ip(request)
                )
                return redirect('dashboard')
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip