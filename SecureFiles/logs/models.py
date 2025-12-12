from django.db import models
from django.conf import settings

class SecurityLog(models.Model):
    ACTION_CHOICES = (
        ('LOGIN_SUCCESS', 'Login Success'),
        ('LOGIN_FAILED', 'Login Failed'),
        ('LOGOUT', 'Logout'),
        ('REGISTRATION', 'Registration'),
        ('FILE_UPLOAD', 'File Upload'),
        ('FILE_DOWNLOAD', 'File Download'),
        ('FILE_SHARED', 'File Shared'),
        ('UNAUTHORIZED_ACCESS', 'Unauthorized Access'),
        ('UNAUTHORIZED_DOWNLOAD', 'Unauthorized Download'),
        ('FILE_INTEGRITY_VIOLATION', 'File Integrity Violation'),
        ('FILE_DECRYPTION_ERROR', 'File Decryption Error'),
        ('FILE_UPLOAD_ERROR', 'File Upload Error'),
        ('VIEW_ACCESS', 'View Access'),
    )
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.action} - {self.user.username if self.user else 'Anonymous'} - {self.timestamp}"