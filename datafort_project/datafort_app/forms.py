from django import forms

from datafort_app.models import UploadedFile

class PasswordForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))

class UploadFileForm(forms.ModelForm):
    class Meta:
        model = UploadedFile
        fields = ['original_file']
        widgets = {
            'original_file': forms.FileInput(attrs={'class': 'form-control-file'}),
        }
