# sms_api/models.py

from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils import timezone
from phonenumber_field.modelfields import PhoneNumberField
from django.utils.translation import gettext_lazy as _
import uuid
from django.conf import settings
from django.contrib.auth import get_user_model

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Make phone_number required and unique, with max length to accommodate country codes
    phone_number = models.CharField(max_length=20, unique=True, null=True)
    company_name = models.CharField(max_length=255, unique=True, blank=True, null=True)
    tokens_balance = models.IntegerField(default=0)
    metadata = models.JSONField(default=dict, blank=True)
    
    # Make username not required
    username = models.CharField(
        max_length=150,
        unique=True,
        blank=True,
        null=True,
        help_text=_('Optional. 150 characters or fewer.')
    )
    
    # Make email required and unique
    email = models.EmailField(unique=True, null=True)
    
    # Email verification fields
    email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=64, blank=True, null=True)
    token_created_at = models.DateTimeField(blank=True, null=True)
    token_expiration = models.DateTimeField(blank=True, null=True)
    
    # Set company_name as the username field for authentication
    USERNAME_FIELD = 'company_name'
    REQUIRED_FIELDS = ['email', 'phone_number']  # Both email and phone_number are required
    
    def __str__(self):
        return str(self.company_name)
    
    def save(self, *args, **kwargs):
        # If username is not provided, use company_name as username
        if not self.username:
            self.username = str(self.company_name)
        super().save(*args, **kwargs)



class SMSTemplate(models.Model):
    """Reusable message templates for campaigns"""
    CATEGORY_CHOICES = [
        ('onboarding', 'Onboarding'),
        ('transactional', 'Transactional'),
        ('reminder', 'Reminder'),
        ('marketing', 'Marketing'),
        ('other', 'Other'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='templates')
    name = models.CharField(max_length=100)
    content = models.TextField()
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='other')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used = models.DateTimeField(null=True, blank=True)
    
    def use_template(self):
        """Update last_used timestamp when template is used"""
        self.last_used = timezone.now()
        self.save(update_fields=['last_used'])
        
    def __str__(self):
        return self.name


class ContactGroup(models.Model):
    """Contact groups for organizing contacts (previously PhoneBook)"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='contact_groups')
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('user', 'name')
        ordering = ['name']
        verbose_name = 'Contact Group'
        verbose_name_plural = 'Contact Groups'
    
    def __str__(self):
        return self.name
    
    def contact_count(self):
        """Return the number of contacts in this group"""
        return self.contacts.count()


class Contact(models.Model):
    """Individual contacts in contact groups"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, null=True, blank=True)
    group = models.ForeignKey(ContactGroup, on_delete=models.CASCADE, related_name='contacts', null=True, blank=True)
    phone_number = models.CharField(max_length=20)
    last_message_sent = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('group', 'phone_number')
        ordering = ['name', 'phone_number']
    
    def __str__(self):
        return f"{self.name} ({self.phone_number})"
    
    def save(self, *args, **kwargs):
        # Ensure phone number is properly formatted
        if not self.phone_number.startswith('+'):
            # Default to Kenya format if no country code
            if self.phone_number.startswith('0'):
                self.phone_number = f"+254{self.phone_number[1:]}"
            else:
                self.phone_number = f"+254{self.phone_number}"
                
        super().save(*args, **kwargs)


class Campaign(models.Model):
    """Model for SMS campaigns"""
    
    class Status(models.TextChoices):
        DRAFT = 'draft', 'Draft'
        SCHEDULED = 'scheduled', 'Scheduled'
        PROCESSING = 'processing', 'Processing'
        PAUSED = 'paused', 'Paused'
        COMPLETED = 'completed', 'Completed'
        CANCELLED = 'cancelled', 'Cancelled'
        FAILED = 'failed', 'Failed'

    class Type(models.TextChoices):
        BULK = 'bulk', 'Bulk SMS'
        PERSONALIZED = 'personalized', 'Personalized SMS'
        TEMPLATE = 'template', 'Template-based'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='campaigns')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    type = models.CharField(max_length=20, choices=Type.choices, default=Type.BULK)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
    
    # Content and Recipients
    message = models.TextField()
    template = models.ForeignKey('MessageTemplate', on_delete=models.SET_NULL, null=True, blank=True)
    groups = models.ManyToManyField('ContactGroup', related_name='campaigns')
    recipient_count = models.IntegerField(default=0)
    
    # Scheduling
    scheduled_time = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Sender Configuration
    sender_id = models.CharField(max_length=11, blank=True)  # Africa's Talking sender ID limit
    
    # Tracking
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['scheduled_time']),
        ]

    def __str__(self):
        return f"{self.name} ({self.status})"

    def get_recipients_count(self):
        """Calculate total number of recipients across all groups"""
        return Contact.objects.filter(group__in=self.groups.all()).distinct().count()

    def update_recipient_count(self):
        """Update the recipient count"""
        self.recipient_count = self.get_recipients_count()
        self.save(update_fields=['recipient_count'])

    def start_campaign(self):
        """Start the campaign"""
        if self.status != self.Status.DRAFT:
            raise ValueError("Campaign can only be started from draft status")

        self.status = self.Status.PROCESSING
        self.started_at = timezone.now()
        self.save(update_fields=['status', 'started_at', 'updated_at'])

    def pause_campaign(self):
        """Pause the campaign"""
        if self.status not in [self.Status.PROCESSING, self.Status.SCHEDULED]:
            raise ValueError("Only processing or scheduled campaigns can be paused")

        self.status = self.Status.PAUSED
        self.save(update_fields=['status', 'updated_at'])

    def resume_campaign(self):
        """Resume the campaign"""
        if self.status != self.Status.PAUSED:
            raise ValueError("Only paused campaigns can be resumed")

        self.status = self.Status.PROCESSING
        self.save(update_fields=['status', 'updated_at'])

    def cancel_campaign(self):
        """Cancel the campaign"""
        if self.status in [self.Status.COMPLETED, self.Status.CANCELLED]:
            raise ValueError("Cannot cancel completed or already cancelled campaigns")

        self.status = self.Status.CANCELLED
        self.save(update_fields=['status', 'updated_at'])

    def complete_campaign(self):
        """Mark campaign as completed"""
        self.status = self.Status.COMPLETED
        self.completed_at = timezone.now()
        self.save(update_fields=['status', 'completed_at', 'updated_at'])

    def get_statistics(self):
        """Get campaign statistics"""
        messages = self.messages.all()
        return {
            'total_messages': messages.count(),
            'delivered': messages.filter(status=SMSMessage.Status.DELIVERED).count(),
            'failed': messages.filter(status=SMSMessage.Status.FAILED).count(),
            'pending': messages.filter(status=SMSMessage.Status.PENDING).count(),
            'sent': messages.filter(status=SMSMessage.Status.SENT).count(),
        }


class SMSMessage(models.Model):
    """Individual SMS messages sent within campaigns"""
    STATUS_CHOICES = [
        ('queued', 'Queued'),
        ('sending', 'Sending'),
        ('sent', 'Sent'),
        ('delivered', 'Delivered'),
        ('failed', 'Failed'),
        ('rejected', 'Rejected'),
    ]
    
    DELIVERY_REPORT_CHOICES = [
        ('pending', 'Pending'),
        ('delivered', 'Delivered'),
        ('failed', 'Failed'),
        ('expired', 'Expired'),
        ('rejected', 'Rejected'),
        ('unknown', 'Unknown'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    campaign = models.ForeignKey(Campaign, on_delete=models.CASCADE, related_name='messages', null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='messages')
    contact = models.ForeignKey(Contact, on_delete=models.SET_NULL, related_name='messages', null=True, blank=True)
    recipient = models.CharField(max_length=20)
    content = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='queued')
    delivery_status = models.CharField(max_length=20, choices=DELIVERY_REPORT_CHOICES, default='pending')
    delivery_time = models.DateTimeField(null=True, blank=True)
    message_id = models.CharField(max_length=100, null=True, blank=True, help_text="Message ID from the SMS provider")
    segments = models.IntegerField(default=1, help_text="Number of SMS segments")
    cost = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    error_message = models.TextField(blank=True, null=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"SMS to {self.recipient} ({self.status})"
    
    def update_delivery_status(self, status, delivery_time=None):
        """Update delivery status and time"""
        self.delivery_status = status
        
        if status == 'delivered' and not self.delivery_time:
            self.delivery_time = delivery_time or timezone.now()
            
        if self.campaign and status in ['delivered', 'failed', 'expired', 'rejected']:
            # Update campaign stats if needed
            self.campaign.updated_at = timezone.now()
            
            # If all messages are delivered or failed, mark campaign as completed
            remaining = SMSMessage.objects.filter(
                campaign=self.campaign, 
                delivery_status='pending'
            ).count()
            
            if remaining == 0:
                self.campaign.status = 'completed'
                self.campaign.completed_at = timezone.now()
                self.campaign.save()
            
        self.save(update_fields=['delivery_status', 'delivery_time', 'updated_at'])


class Payment(models.Model):
    """Payment records"""
    PAYMENT_STATUS = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=PAYMENT_STATUS, default='pending')
    payment_date = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class WebhookEndpoint(models.Model):
    """Webhook configuration for real-time events"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webhooks')
    url = models.URLField()
    is_active = models.BooleanField(default=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class MessageTemplate(models.Model):
    """Model for managing message templates with content verification"""
    
    class VerificationStatus(models.TextChoices):
        PENDING = 'pending', 'Pending Review'
        APPROVED = 'approved', 'Approved'
        REJECTED = 'rejected', 'Rejected'
        FLAGGED = 'flagged', 'Flagged for Review'

    class TemplateCategory(models.TextChoices):
        MARKETING = 'marketing', 'Marketing'
        TRANSACTIONAL = 'transactional', 'Transactional'
        NOTIFICATION = 'notification', 'Notification'
        OTP = 'otp', 'One-Time Password'
        REMINDER = 'reminder', 'Reminder'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    content = models.TextField()
    category = models.CharField(
        max_length=20,
        choices=TemplateCategory.choices,
        default=TemplateCategory.MARKETING
    )
    verification_status = models.CharField(
        max_length=20,
        choices=VerificationStatus.choices,
        default=VerificationStatus.PENDING
    )
    rejection_reason = models.TextField(null=True, blank=True)
    variables = models.JSONField(default=list)  # List of variables in the template
    metadata = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    usage_count = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.name} - {self.category} ({self.verification_status})"

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['verification_status']),
            models.Index(fields=['category']),
            models.Index(fields=['user', 'is_active'])
        ]