from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid

class SubscriptionPlan(models.Model):
    """Model for different subscription plans"""
    PLAN_TYPES = [
        ('demo', 'Demo Plan'),
        ('starter', 'Starter Package'),
        ('business', 'Business Package'),
        ('enterprise', 'Enterprise Package'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    plan_type = models.CharField(max_length=20, choices=PLAN_TYPES)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    tokens = models.IntegerField()
    validity_days = models.IntegerField()
    features = models.JSONField(default=list)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.tokens} tokens"

class UserSubscription(models.Model):
    """Model for user subscriptions"""
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('cancelled', 'Cancelled'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.PROTECT)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    auto_renew = models.BooleanField(default=False)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def is_valid(self):
        """Check if subscription is still valid"""
        return (
            self.status == 'active' and 
            self.start_date <= timezone.now() <= self.end_date
        )

    def __str__(self):
        return f"{self.user.company_name} - {self.plan.name}"

class TokenTransaction(models.Model):
    """Model for token transactions"""
    TRANSACTION_TYPES = [
        ('purchase', 'Token Purchase'),
        ('usage', 'Token Usage'),
        ('refund', 'Token Refund'),
        ('bonus', 'Bonus Tokens'),
        ('expiry', 'Token Expiry'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    tokens = models.IntegerField()
    amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    reference = models.CharField(max_length=100, unique=True)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.company_name} - {self.transaction_type} - {self.tokens} tokens"

class TokenPricing(models.Model):
    """Model for token pricing tiers"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    min_tokens = models.IntegerField()
    max_tokens = models.IntegerField()
    buying_price = models.DecimalField(max_digits=10, decimal_places=2)
    selling_price = models.DecimalField(max_digits=10, decimal_places=2)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.min_tokens}-{self.max_tokens} tokens: KES {self.selling_price}"

    class Meta:
        ordering = ['min_tokens'] 