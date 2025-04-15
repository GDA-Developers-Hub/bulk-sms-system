# sms_api/admin.py

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    User, ContactGroup, Contact, SMSCampaign, 
    SMSMessage, Payment, SMSTemplate, WebhookEndpoint
)

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'company_name', 'tokens_balance', 'is_staff')
    fieldsets = BaseUserAdmin.fieldsets + (
        ('SMS Platform Info', {'fields': ('phone_number', 'company_name', 'tokens_balance', 'metadata')}),
    )


@admin.register(ContactGroup)
class ContactGroupAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'description', 'contact_count', 'created_at')
    search_fields = ('name', 'description', 'user__username')
    list_filter = ('created_at',)
    
    def contact_count(self, obj):
        return obj.contacts.count()
    contact_count.short_description = 'Number of Contacts'


@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'phone_number', 'group', 'last_message_sent', 'created_at')
    search_fields = ('name', 'phone_number', 'group__name', 'group__user__username')
    list_filter = ('group', 'created_at', 'last_message_sent')


@admin.register(SMSCampaign)
class SMSCampaignAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'status', 'created_at')
    list_filter = ('status',)
    search_fields = ('name', 'user__username', 'message')


@admin.register(SMSMessage)
class SMSMessageAdmin(admin.ModelAdmin):
    list_display = ('recipient', 'user', 'status', 'created_at')
    list_filter = ('status',)
    search_fields = ('recipient', 'content', 'user__username')


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('user', 'amount', 'status', 'payment_date', 'created_at')
    list_filter = ('status',)
    search_fields = ('user__username',)


@admin.register(SMSTemplate)
class SMSTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'category', 'last_used', 'created_at')
    list_filter = ('category',)
    search_fields = ('name', 'content', 'user__username')


@admin.register(WebhookEndpoint)
class WebhookEndpointAdmin(admin.ModelAdmin):
    list_display = ('url', 'user', 'is_active', 'created_at')
    list_filter = ('is_active',)
    search_fields = ('url', 'user__username')