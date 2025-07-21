from django.db import models
from vms_app.models import User

# Model for system-wide messages sent by Admins (or other users)
class Message(models.Model):
    # The user who sent the message (typically an admin)
    sender = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="sent_messages"  # Allows reverse lookup: user.sent_messages.all()
    )

    # The actual message content
    content = models.TextField()

    # Timestamp when the message was created
    created_at = models.DateTimeField(auto_now_add=True)

    # Optional subject/title for message (uncomment to use)
    # subject = models.CharField(max_length=255, blank=True)

    # Note: This model is used for broadcast messages to all users (especially employees),
    # so no need for a specific recipient field.

    def __str__(self):
        return f"Message from {self.sender.username} at {self.created_at}"
