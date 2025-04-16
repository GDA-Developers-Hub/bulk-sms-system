# sms_api/admin.py

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    User, Contact, ContactGroup, Campaign, SMSMessage,
    Payment, WebhookEndpoint, MessageTemplate, SMSTemplate
)

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('company_name', 'email', 'phone_number', 'tokens_balance', 'is_staff', 'email_verified')
    search_fields = ('company_name', 'email', 'phone_number')
    ordering = ('company_name',)
    list_filter = ('is_staff', 'is_active', 'email_verified')
    
    fieldsets = (
        (None, {'fields': ('company_name', 'email', 'password')}),
        ('Personal info', {'fields': ('phone_number', 'tokens_balance')}),
        ('Verification', {'fields': ('email_verified', 'verification_token', 'token_created_at', 'token_expiration')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
        ('Additional Info', {'fields': ('metadata',)}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('company_name', 'email', 'phone_number', 'password1', 'password2'),
        }),
    )

@admin.register(ContactGroup)
class ContactGroupAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'contact_count', 'created_at')
    search_fields = ('name', 'user__company_name')
    list_filter = ('created_at',)

@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'phone_number', 'group', 'last_message_sent')
    search_fields = ('name', 'phone_number')
    list_filter = ('group', 'created_at')

@admin.register(Campaign)
class CampaignAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'type', 'status', 'recipient_count', 'created_at')
    search_fields = ('name', 'user__company_name')
    list_filter = ('status', 'type', 'created_at')
    readonly_fields = ('recipient_count', 'started_at', 'completed_at')
    filter_horizontal = ('groups',)

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(user=request.user)

@admin.register(SMSMessage)
class SMSMessageAdmin(admin.ModelAdmin):
    list_display = ('recipient', 'status', 'delivery_status', 'campaign', 'created_at')
    search_fields = ('recipient', 'message_id')
    list_filter = ('status', 'delivery_status', 'created_at')
    readonly_fields = ('delivery_time', 'message_id', 'segments', 'cost')

@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('user', 'amount', 'status', 'payment_date', 'created_at')
    search_fields = ('user__company_name',)
    list_filter = ('status', 'created_at')
    readonly_fields = ('payment_date',)

@admin.register(WebhookEndpoint)
class WebhookEndpointAdmin(admin.ModelAdmin):
    list_display = ('user', 'url', 'is_active', 'created_at')
    search_fields = ('user__company_name', 'url')
    list_filter = ('is_active', 'created_at')

@admin.register(MessageTemplate)
class MessageTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'category', 'verification_status', 'is_active', 'usage_count')
    search_fields = ('name', 'user__company_name', 'content')
    list_filter = ('category', 'verification_status', 'is_active', 'created_at')
    readonly_fields = ('usage_count', 'last_used_at')

@admin.register(SMSTemplate)
class SMSTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'category', 'created_at', 'last_used')
    search_fields = ('name', 'user__company_name', 'content')
    list_filter = ('category', 'created_at')
    readonly_fields = ('last_used',)