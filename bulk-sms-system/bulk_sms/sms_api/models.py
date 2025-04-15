# sms_api/models.py

from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils import timezone
from phonenumber_field.modelfields import PhoneNumberField
from django.utils.translation import gettext_lazy as _
import uuid

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


class SMSCampaign(models.Model):
    """SMS campaigns for sending messages"""
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('scheduled', 'Scheduled'),
        ('sending', 'Sending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    TYPE_CHOICES = [
        ('single', 'Single Message'),
        ('bulk', 'Bulk Message'),
        ('periodic', 'Periodic Message'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='campaigns')
    name = models.CharField(max_length=100)
    message = models.TextField()
    sender_id = models.CharField(max_length=20)
    type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='single')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    groups = models.ManyToManyField(ContactGroup, related_name='campaigns', blank=True)
    scheduled_time = models.DateTimeField(null=True, blank=True)
    completed_time = models.DateTimeField(null=True, blank=True)
    recipient_count = models.IntegerField(default=0)
    delivery_rate = models.FloatField(default=0.0)
    template = models.ForeignKey(SMSTemplate, on_delete=models.SET_NULL, 
                                 related_name='campaigns', null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    def get_recipients_count(self):
        """Get total number of recipients for this campaign"""
        if self.groups.exists():
            # Count unique contacts in all selected groups
            contact_ids = Contact.objects.filter(group__in=self.groups.all()).values_list('id', flat=True).distinct()
            return len(contact_ids)
        else:
            # If no groups selected, use the count stored in the model
            return self.recipient_count
    
    def calculate_estimated_cost(self):
        """Calculate the estimated cost of this campaign based on recipient count"""
        # Simple estimation: 1 token per recipient
        # This can be enhanced with more complex logic
        return self.get_recipients_count()
    
    def save(self, *args, **kwargs):
        # If campaign is being marked as completed, set completed_time
        if self.status == 'completed' and not self.completed_time:
            self.completed_time = timezone.now()
        
        super().save(*args, **kwargs)


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
    campaign = models.ForeignKey(SMSCampaign, on_delete=models.CASCADE, related_name='messages', null=True, blank=True)
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
                self.campaign.completed_time = timezone.now()
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