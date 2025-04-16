# sms_api/urls.py

from rest_framework_simplejwt.views import TokenRefreshView
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    RegisterView, EmailVerificationRequestView, EmailVerificationConfirmView, UserViewSet, 
    ContactGroupViewSet, ContactViewSet, CampaignViewSet,
    SMSMessageViewSet, PaymentViewSet, SMSTemplateViewSet, WebhookEndpointViewSet,
    CustomTokenObtainPairView, RegisterView, LoginView, LogoutView, ChangePasswordView, 
    ResetPasswordRequestView, ResetPasswordConfirmView, UserProfileView
)

# Set up the router for ViewSets
router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'groups', ContactGroupViewSet, basename='group')
router.register(r'contacts', ContactViewSet, basename='contact')
router.register(r'campaigns', CampaignViewSet, basename='campaign')
router.register(r'messages', SMSMessageViewSet, basename='message')
router.register(r'payments', PaymentViewSet, basename='payment')
router.register(r'templates', SMSTemplateViewSet, basename='template')
router.register(r'webhooks', WebhookEndpointViewSet, basename='webhook')
router.register(r'sms-templates', SMSTemplateViewSet)
router.register(r'sms-messages', SMSMessageViewSet)

urlpatterns = [
    # Include all routes from the router
    path('', include(router.urls)),
    
    # Authentication endpoints
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # Registration and verification
    path('register/', RegisterView.as_view(), name='register'),
    path('email/verify-request/', EmailVerificationRequestView.as_view(), name='email-verify-request'),
    path('email/verify-confirm/', EmailVerificationConfirmView.as_view(), name='email-verify-confirm'),
    # Password management
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('reset-password/request/', ResetPasswordRequestView.as_view(), name='reset_password_request'),
    path('reset-password/confirm/', ResetPasswordConfirmView.as_view(), name='reset_password_confirm'),
    
    # User profile
    path('profile/', UserProfileView.as_view(), name='profile'),
    
    # Custom callback URLs
    path('callbacks/delivery-reports/', SMSMessageViewSet.as_view({'post': 'delivery_callback'}), name='africas-talking-callback'),
]
