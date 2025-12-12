from django.db import models
from django.conf import settings
import os

def encrypted_file_upload_path(instance, filename):
    return f'encrypted_files/user_{instance.owner.id}/{filename}'

class SecureFile(models.Model):
    PERMISSION_CHOICES = (
        ('read', 'Read Only'),
        ('edit', 'Can Edit'),
    )
    
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='uploaded_files')
    original_filename = models.CharField(max_length=255)
    encrypted_file = models.FileField(upload_to=encrypted_file_upload_path)
    encrypted_aes_key = models.TextField()  # AES key encrypted with owner's RSA public key
    file_hash = models.CharField(max_length=64)  # SHA-256 hash
    file_size = models.BigIntegerField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.original_filename

class FileShare(models.Model):
    PERMISSION_CHOICES = (
        ('read', 'Read Only'),
        ('edit', 'Can Edit'),
    )
    
    file = models.ForeignKey(SecureFile, on_delete=models.CASCADE, related_name='shares')
    shared_with = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shared_files')
    permission = models.CharField(max_length=4, choices=PERMISSION_CHOICES, default='read')
    shared_at = models.DateTimeField(auto_now_add=True)
    encrypted_aes_key = models.TextField()  # AES key encrypted with shared user's RSA public key
    
    class Meta:
        unique_together = ('file', 'shared_with')
    
    def __str__(self):
        return f"{self.file.original_filename} shared with {self.shared_with.username}"