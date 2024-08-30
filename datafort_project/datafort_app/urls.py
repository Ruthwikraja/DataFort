# cryptography_app/urls.py
from django.urls import path
from datafort_app.views import home, upload_file, encrypt, download, steganography

urlpatterns = [
    path('', home, name='home'),
    path('upload/', upload_file, name='upload_file'),
    path('encrypt/<int:file_id>/', encrypt, name='encrypt_file'),
    path('download/<int:file_id>/', download, name='download_file'),
    path('steganography/<int:file_id>/', steganography, name='steganography'),
    # Add more paths for additional views as needed
]
