from django import forms
from .models import SecureFile, FileShare

class FileUploadForm(forms.ModelForm):
    class Meta:
        model = SecureFile
        fields = ['original_filename']

class FileShareForm(forms.ModelForm):
    class Meta:
        model = FileShare
        fields = ['shared_with', 'permission']
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        self.file = kwargs.pop('file', None)
        super().__init__(*args, **kwargs)
        
        if self.user:
            # Exclude current user from sharing options
            self.fields['shared_with'].queryset = self.fields['shared_with'].queryset.exclude(id=self.user.id)