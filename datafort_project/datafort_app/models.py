# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.utils.crypto import get_random_string

# Enhanced User model with preferences
class User(AbstractUser):
    default_algorithm = models.ForeignKey('Algorithm', on_delete=models.SET_NULL, null=True)
    key_management_preference = models.CharField(max_length=50)

# File model with FileField for storage
class UploadedFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    original_file = models.FileField(upload_to='uploaded_files/')
    encrypted_file = models.FileField(upload_to='encrypted_files/', null=True)
    file_type = models.CharField(max_length=50)
    file_size = models.IntegerField()
    upload_time = models.DateTimeField(auto_now_add=True)

    algorithm = models.ForeignKey('Algorithm', on_delete=models.PROTECT)
    keys = models.ManyToManyField('Key')

# Algorithm model
class Algorithm(models.Model):
    name = models.CharField(max_length=50)
    description = models.TextField()
    security_level = models.CharField(max_length=20)
    supported_types = models.TextField()

# Key model (password-based storage)
class Key(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.ForeignKey('UploadedFile', on_delete=models.CASCADE)

    key_data = models.BinaryField()
    key_size = models.IntegerField()
    key_type = models.CharField(max_length=50)
    generation_method = models.CharField(max_length=50)
    security_settings = models.TextField()

    key_password_hash = models.CharField(max_length=128)
    algorithm = models.ForeignKey('Algorithm', on_delete=models.CASCADE)

    def set_key_password(self, password):
        salt = get_random_string(64)
        hasher = PBKDF2PasswordHasher()
        password_hash = hasher.encode(password, salt, iterations=100000)
        self.key_password_hash = password_hash
        self.save()

    def check_key_password(self, password):
        hasher = PBKDF2PasswordHasher()
        return hasher.verify(password, self.key_password_hash)

# Educational Resource model
class EducationalResource(models.Model):
    title = models.CharField(max_length=255)
    content = models.TextField()

# Session model with detailed logs
class Session(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.ForeignKey(UploadedFile, on_delete=models.CASCADE)
    algorithm = models.ForeignKey(Algorithm, on_delete=models.PROTECT)
    key = models.ForeignKey(Key, on_delete=models.PROTECT)
    progress = models.IntegerField()
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True)

# Detailed session logs
class SessionLog(models.Model):
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    message = models.TextField()

# Steganography model
class Steganography(models.Model):
    uploaded_file = models.OneToOneField(UploadedFile, on_delete=models.CASCADE)
    carrier_file = models.FileField(upload_to='carrier_files/', null=True)
    embedded_data = models.BinaryField()
    technique = models.CharField(max_length=50, choices=[
        ('LSB', 'Least Significant Bit'),
        ('FD', 'Frequency Domain'),
        # Add more choices for other techniques
    ])

    # Additional fields based on technique
    lsb_embedded_data = models.BinaryField(null=True)
    frequency_embedded_data = models.BinaryField(null=True)
    # Add more fields for other techniques as needed

    def get_embedded_data(self):
        if self.technique == 'LSB':
            return self.lsb_embedded_data
        elif self.technique == 'FD':
            return self.frequency_embedded_data
        # Add more conditions for other techniques

    def set_embedded_data(self, data):
        if self.technique == 'LSB':
            self.lsb_embedded_data = data
        elif self.technique == 'FD':
            self.frequency_embedded_data = data
        # Add more conditions for other techniques

    def save(self, *args, **kwargs):
        # Automatically set embedded_data based on the selected technique
        self.set_embedded_data(self.embedded_data)
        super().save(*args, **kwargs)