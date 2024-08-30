
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .forms import UploadFileForm, PasswordForm
from .algorithms import encrypt_aes, decrypt_aes, generate_rsa_keypair, hash_sha256, process_frequency_domain_steganography, process_lsb_steganography
from .models import UploadedFile, Algorithm, Key, Session, Steganography
from django.http import HttpResponse
import os

@login_required
def home(request):
    return render(request, 'home.html')

@login_required
def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.save(commit=False)
            uploaded_file.user = request.user
            uploaded_file.file_size = uploaded_file.original_file.size
            uploaded_file.file_type = uploaded_file.original_file.name.split('.')[-1]
            uploaded_file.save()

            return redirect('encrypt', file_id=uploaded_file.id)
    else:
        form = UploadFileForm()
    return render(request, 'upload_file.html', {'form': form})

@login_required
def encrypt(request, file_id):
    uploaded_file = get_object_or_404(UploadedFile, id=file_id, user=request.user)

    if request.method == 'POST':
        form = PasswordForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            salt = os.urandom(16)

            encrypted_data = encrypt_aes(uploaded_file.original_file.read(), password, salt)

            encrypted_file_path = f'encrypted_files/encrypted_{uploaded_file.original_file.name}'
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)

            uploaded_file.salt = salt
            uploaded_file.encrypted_file.name = encrypted_file_path
            uploaded_file.save()

            return redirect('download', file_id=uploaded_file.id)
    else:
        form = PasswordForm()
    return render(request, 'encrypt.html', {'form': form, 'file': uploaded_file})

@login_required
def download(request, file_id):
    uploaded_file = get_object_or_404(UploadedFile, id=file_id, user=request.user)

    if request.method == 'POST':
        form = PasswordForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']

            decrypted_data = decrypt_aes(uploaded_file.encrypted_file.read(), password, uploaded_file.salt)

            response = HttpResponse(decrypted_data, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename={uploaded_file.original_file.name}'
            return response
    else:
        form = PasswordForm()
    return render(request, 'download.html', {'form': form, 'file': uploaded_file})

@login_required
def steganography(request, file_id):
    uploaded_file = get_object_or_404(UploadedFile, id=file_id, user=request.user)

    if request.method == 'POST':
        carrier_file = request.FILES.get('carrier_file')
        technique = request.POST.get('technique')

        # Process steganography based on the selected technique
        if technique == 'LSB':
            embedded_data = process_lsb_steganography(carrier_file)
        elif technique == 'FD':
            embedded_data = process_frequency_domain_steganography(carrier_file)
        # Add more conditions for other techniques

        # Save the steganography details
        steganography_obj, created = Steganography.objects.get_or_create(
            uploaded_file=uploaded_file,
            defaults={
                'carrier_file': carrier_file,
                'embedded_data': embedded_data,
                'technique': technique,
            }
        )

        return redirect('home')

    return render(request, 'steganography.html', {'file': uploaded_file})