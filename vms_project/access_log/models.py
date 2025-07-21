from django.db import models
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from device.models import Device

# Model to track access/attendance logs of employees and guests
class AccessLog(models.Model):
    # Choices for identifying the person type
    PERSON_TYPE_CHOICES = (
        ('employee', 'Employee'),
        ('guest', 'Guest'),
    )

    # Type of person (employee or guest)
    person_type = models.CharField(max_length=10, choices=PERSON_TYPE_CHOICES)

    # ID of the employee or guest
    person_id = models.PositiveIntegerField()

    # Used to link either Guest or EmployeeProfile (Generic relation)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    person = GenericForeignKey('content_type', 'person_id')

    # Device used during check-in/out (nullable if none scanned)
    device = models.ForeignKey(Device, max_length=100, null=True, blank=True, on_delete=models.SET_NULL)

    # The security user who performed the scan
    scanned_by = models.ForeignKey(
        'vms_app.User',
        on_delete=models.SET_NULL,
        null=True,
        limit_choices_to={'role': 'security'}
    )

    # Timestamp for when the person checked in
    time_in = models.DateTimeField(auto_now_add=True)

    # Timestamp for when the person checked out (nullable until logged out)
    time_out = models.DateTimeField(null=True, blank=True)

    # Status of the access: "in" or "out"
    status = models.CharField(max_length=10, choices=(('in', 'In'), ('out', 'Out')))

    def __str__(self):
        """
        String representation of the log entry,
        showing the person and device (if available).
        """
        name = self.person_name or "Unknown"
        device = self.device.serial_number if self.device else "No Device"
        return f"{name} ({device})"

    @property
    def person_name(self):
        """
        Returns the string version of the person object,
        assuming Guest and EmployeeProfile implement __str__ properly.
        """
        try:
            return str(self.person)
        except Exception:
            return "Unknown"
