from django.db import models
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from device.models import Device

# Create your models here.


class AccessLog(models.Model):
    PERSON_TYPE_CHOICES = (
        ('employee', 'Employee'),
        ('guest', 'Guest'),
    )
    person_type = models.CharField(max_length=10, choices=PERSON_TYPE_CHOICES)
    person_id = models.PositiveIntegerField()
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    person = GenericForeignKey('content_type', 'person_id')
    device = models.ForeignKey(Device, max_length=100, null=True, blank=True, on_delete=models.SET_NULL)
    scanned_by = models.ForeignKey('vms_app.User', on_delete=models.SET_NULL, null=True, limit_choices_to={'role': 'security'})
    time_in = models.DateTimeField(auto_now_add=True)
    time_out = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=(('in', 'In'), ('out', 'Out')))

    def __str__(self):
        return f"{self.person}"
    
    def __str__(self):
        return f"{self.device}"
    
    @property
    def person_name(self):
        try:
            return str(self.person)  # relies on Guest and EmployeeProfile having a good __str__
        except Exception:
            return "Unknown"
        
    def __str__(self):
        return f"{self.person_name}"
    
    def __str__(self):
        try:
            return self.device.serial_number
        except AttributeError:
            return "No Device"

