from django.contrib import admin
from .models import SecureFile, FileShare

@admin.register(SecureFile)
class SecureFileAdmin(admin.ModelAdmin):
    list_display = ('original_filename', 'owner', 'file_size', 'uploaded_at')
    list_filter = ('owner', 'uploaded_at')
    search_fields = ('original_filename', 'owner__username')

@admin.register(FileShare)
class FileShareAdmin(admin.ModelAdmin):
    list_display = ('file', 'shared_with', 'permission', 'shared_at')
    list_filter = ('permission', 'shared_at')
    search_fields = ('file__original_filename', 'shared_with__username')