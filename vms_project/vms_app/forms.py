# vms_app/forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User

class CustomUserCreationForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('username', 'email', 'role', 'must_change_password')  # Don't include password1/password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password("Welcome$")  # Set default password
        if commit:
            user.save()
        return user
