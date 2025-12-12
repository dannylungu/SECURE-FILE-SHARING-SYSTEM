from django.urls import path
from . import views

urlpatterns = [
    path('admin/', views.admin_logs_view, name='admin_logs'),
]