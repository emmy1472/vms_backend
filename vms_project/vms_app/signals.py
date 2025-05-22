# signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from .models import User

@receiver(post_save, sender=User)
def send_welcome_email(sender, instance, created, **kwargs):
    if created and instance.email:
        send_mail(
            subject='Welcome!',
            message=f'Hello {instance.username}, your account has been created.',
            from_email='emmanuelakinmolayan1@gmail.com',
            recipient_list=[instance.email],
            fail_silently=False,
        )
