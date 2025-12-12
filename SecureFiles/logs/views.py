from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render
from .models import SecurityLog

def is_admin(user):
    return user.role == 'admin'

@login_required
@user_passes_test(is_admin)
def admin_logs_view(request):
    logs = SecurityLog.objects.all()[:100]  # Last 100 logs
    return render(request, 'logs/admin_logs.html', {'logs': logs})