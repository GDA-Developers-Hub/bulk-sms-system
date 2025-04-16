# sms_api/views.py
from rest_framework import viewsets, permissions, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db.models import Q
from rest_framework.views import APIView
from rest_framework.generics import UpdateAPIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import AccessToken
from datetime import timedelta
from django.utils import timezone
import logging
from .models import SMSTemplate, ContactGroup, Contact, WebhookEndpoint, MessageTemplate, Campaign, SMSMessage, Payment
from utils.sms_gateways import (
    validate_african_phone, generate_verification_token, 
    is_token_valid, send_verification_email, format_phone_number, 
    send_verification_email, send_password_reset_email
    )
from .serializers import (
    CustomTokenObtainPairSerializer, RegistrationSerializer, EmailVerificationRequestSerializer, 
    EmailVerificationConfirmSerializer, UserSerializer, TokenRefreshSerializer,
    ChangePasswordSerializer, ResetPasswordRequestSerializer, ResetPasswordConfirmSerializer,
    UserProfileUpdateSerializer, ContactGroupSerializer, ContactSerializer, 
    PaymentSerializer, SMSTemplateSerializer, WebhookEndpointSerializer, 
    SMSMessageSerializer, LoginSerializer, MessageTemplateSerializer, CampaignSerializer
)
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import requests
import uuid
from .services import TemplateVerificationService, SMSService
from .tasks import send_campaign_messages

User = get_user_model()
logger = logging.getLogger(__name__)


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Takes a set of user credentials (company_name, password) and returns an access and refresh JWT pair
    with additional user details.
    """
    serializer_class = CustomTokenObtainPairSerializer

    @swagger_auto_schema(
        operation_description="Obtain JWT token pair with company name and password",
        responses={
            200: openapi.Response(
                description="JWT token pair with user details",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'access': openapi.Schema(type=openapi.TYPE_STRING),
                        'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                        'user_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'company_name': openapi.Schema(type=openapi.TYPE_STRING),
                        'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
                        'email': openapi.Schema(type=openapi.TYPE_STRING),
                        'tokens_balance': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'is_staff': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'is_email_verified': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    }
                )
            ),
            401: "Invalid credentials"
        }
    )
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        # Extract user information from the response data
        user = request.user
        refresh = RefreshToken.for_user(user)
        
        # Set the access and refresh tokens in HttpOnly cookies
        access_token_expiry = timedelta(minutes=15)  # 15 minutes
        refresh_token_expiry = timedelta(days=7)  # 7 days
        
        # Add tokens to HttpOnly cookies
        response.set_cookie(
            'access_token',
            str(refresh.access_token),
            httponly=True,
            secure=True,  # Ensure this is True in production (HTTPS)
            samesite='Strict',
            max_age=access_token_expiry
        )
        
        response.set_cookie(
            'refresh_token',
            str(refresh),
            httponly=True,
            secure=True,  # Ensure this is True in production (HTTPS)
            samesite='Strict',
            max_age=refresh_token_expiry
        )
        
        # Include additional user details in the response
        response.data.update({
            'user_id': str(user.id),
            'company_name': user.company_name,
            'phone_number': user.phone_number,
            'email': user.email,
            'tokens_balance': user.tokens_balance,
            'is_staff': user.is_staff,
            'is_email_verified': user.email_verified,
        })

        return response


class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom token refresh view that preserves user information in the new access token.
    """
    def post(self, request, *args, **kwargs):
        # First, get the standard response from the parent class
        response = super().post(request, *args, **kwargs)
        
        # Get the refresh token from the cookie
        refresh_token = request.COOKIES.get('refresh_token')
        
        if refresh_token:
            # Get the new access token from the response
            new_access_token_str = response.data.get('access')
            
            if new_access_token_str:
                # Decode the old access token to get user information
                old_access_token_str = request.COOKIES.get('access_token')
                
                if old_access_token_str:
                    try:
                        # Parse the old token to get the claims
                        old_token = AccessToken(old_access_token_str)
                        
                        # Create a new token object from the string
                        new_token = AccessToken(new_access_token_str)
                        
                        # Copy user information from old token to new token
                        for claim in ['user_id', 'company_name', 'phone_number', 'email', 
                                     'tokens_balance', 'is_staff', 'is_email_verified']:
                            if claim in old_token:
                                new_token[claim] = old_token[claim]
                        
                        # Set the new access token in HttpOnly cookie
                        access_token_expiry = timedelta(minutes=15)  # 15 minutes
                        
                        response.set_cookie(
                            'access_token',
                            str(new_token),
                            httponly=True,
                            secure=True,  # Ensure this is True in production (HTTPS)
                            samesite='Strict',
                            max_age=int(access_token_expiry.total_seconds())
                        )
                        
                        # Replace response data with success message
                        response.data = {
                            'message': 'Token refreshed successfully.'
                        }
                    except Exception as e:
                        # If there's an error processing the token, log it but continue
                        logger.error(f"Error copying claims during token refresh: {str(e)}")
        
        return response


class RegisterView(APIView):
    """
    API endpoint that allows users to register.
    """
    permission_classes = [AllowAny]
    
    @method_decorator(sensitive_post_parameters('password'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Register a new user account",
        request_body=RegistrationSerializer,
        responses={
            201: openapi.Response(
                description="User registered successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'user_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'email': openapi.Schema(type=openapi.TYPE_STRING),
                        'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
                        'verification_email_sent': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    }
                )
            ),
            400: "Bad request"
        }
    )
    def post(self, request):
        # Pre-process phone number if provided
        if 'phone_number' in request.data:
            is_valid, formatted_number, error = validate_african_phone(request.data['phone_number'])
            if not is_valid:
                return Response({'phone_number': [error]}, status=status.HTTP_400_BAD_REQUEST)
            
            # Update the request data with formatted number
            request.data['phone_number'] = formatted_number
        
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Generate verification token
            token = generate_verification_token()
            user.verification_token = token
            user.token_created_at = timezone.now()
            user.token_expiration = timezone.now() + timedelta(hours=24)
            user.save()
            
            # Send verification email
            success, message = send_verification_email(user, token)
            
            if not success:
                logger.error(f"Failed to send verification email to {user.email}: {message}")
            
            return Response({
                'message': 'User registered successfully. Please check your email for verification instructions.',
                'user_id': str(user.id),
                'email': user.email,
                'phone_number': user.phone_number,
                'verification_email_sent': success
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationRequestView(APIView):
    """
    API endpoint for requesting email verification.
    """
    permission_classes = [AllowAny]
    
    @swagger_auto_schema(
        operation_description="Request email verification token",
        request_body=EmailVerificationRequestSerializer,
        responses={
            200: openapi.Response(
                description="Verification email sent successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'verification_email_sent': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    }
                )
            ),
            404: "User not found",
            400: "Bad request"
        }
    )
    def post(self, request):
        serializer = EmailVerificationRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                user = User.objects.get(email=email)
                
                # If already verified, no need to send another email
                if user.email_verified:
                    return Response({
                        'message': 'Your email is already verified.',
                        'verification_email_sent': False
                    }, status=status.HTTP_200_OK)
                
                # Generate new verification token
                token = generate_verification_token()
                user.verification_token = token
                user.token_created_at = timezone.now()
                user.token_expiration = timezone.now() + timedelta(hours=24)
                user.save()
                
                # Send verification email
                success, message = send_verification_email(user, token)
                
                if not success:
                    logger.error(f"Failed to send verification email to {email}: {message}")
                
                return Response({
                    'message': 'Verification email sent successfully.',
                    'verification_email_sent': success
                }, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({
                    'message': 'User with this email does not exist.'
                }, status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationConfirmView(APIView):
    """
    API endpoint for confirming email verification with token.
    """
    permission_classes = [AllowAny]
    
    @swagger_auto_schema(
        operation_description="Confirm email verification with token",
        request_body=EmailVerificationConfirmSerializer,
        responses={
            200: openapi.Response(
                description="Email verified successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'email': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            400: "Invalid token or Bad request"
        }
    )
    def post(self, request):
        serializer = EmailVerificationConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            
            try:
                user = User.objects.get(verification_token=token)
                
                # Mark email as verified
                user.email_verified = True
                user.verification_token = None  # Clear the token
                user.token_created_at = None
                user.token_expiration = None
                user.save()
                
                return Response({
                    'message': 'Email verified successfully.',
                    'email': user.email
                }, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({
                    'message': 'Invalid verification token.'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """
    API endpoint for user login with company name and password.
    """
    permission_classes = [AllowAny]
    
    @swagger_auto_schema(
        operation_description="Login with company name and password",
        request_body=LoginSerializer,
        responses={
            200: openapi.Response(
                description="Login successful with JWT tokens",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                        'access': openapi.Schema(type=openapi.TYPE_STRING),
                        'user_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'company_name': openapi.Schema(type=openapi.TYPE_STRING),
                        'email': openapi.Schema(type=openapi.TYPE_STRING),
                        'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
                        'tokens_balance': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'is_email_verified': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    }
                )
            ),
            400: "Bad request",
            401: "Invalid credentials"
        }
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Get tokens for the user
            refresh = RefreshToken.for_user(user)
            
            # Update last login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user_id': str(user.id),
                'company_name': user.company_name,
                'email': user.email,
                'phone_number': user.phone_number,
                'tokens_balance': user.tokens_balance,  # also removed space in key name
                'is_email_verified': user.email_verified,
            })

        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SMSTemplateViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows SMS templates to be viewed or edited.
    """
    queryset = SMSTemplate.objects.all()
    serializer_class = SMSTemplateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """
        This view returns templates for the currently authenticated user.
        """
        return SMSTemplate.objects.filter(user=self.request.user)

    @swagger_auto_schema(
        operation_description="List all SMS templates belonging to the authenticated user"
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Create a new SMS template"
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)


class WebhookEndpointViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows webhook endpoints to be viewed or edited.
    """
    queryset = WebhookEndpoint.objects.all()
    serializer_class = WebhookEndpointSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """
        This view returns webhook endpoints for the currently authenticated user.
        """
        return WebhookEndpoint.objects.filter(user=self.request.user)
    
    @swagger_auto_schema(
        operation_description="List all webhook endpoints configured by the authenticated user"
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Create a new webhook endpoint",
        request_body=WebhookEndpointSerializer
    )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Add the current user
        serializer.save(user=request.user)
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    @swagger_auto_schema(
        operation_description="Test a webhook endpoint by sending a test event",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'event_type': openapi.Schema(type=openapi.TYPE_STRING, description='Type of event to simulate (message.sent, message.delivered, etc.)'),
            },
            required=['event_type']
        ),
        responses={
            200: openapi.Response(
                description="Test webhook sent",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            400: "Bad request"
        }
    )
    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """Send a test webhook event to the endpoint"""
        webhook = self.get_object()
        
        if not webhook.is_active:
            return Response(
                {"detail": "Cannot test inactive webhook."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        event_type = request.data.get('event_type', 'test.event')
        
        # Create a test event payload
        payload = {
            'id': str(uuid.uuid4()),
            'event': event_type,
            'created': timezone.now().isoformat(),
            'data': {
                'test': True,
                'message': 'This is a test webhook event'
            }
        }
        
        # Send the webhook
        try:
            response = requests.post(
                webhook.url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            
            webhook.metadata.update({
                'last_test': {
                    'timestamp': timezone.now().isoformat(),
                    'event_type': event_type,
                    'status_code': response.status_code,
                    'response': response.text[:500]  # Limit response size
                }
            })
            webhook.save(update_fields=['metadata', 'updated_at'])
            
            if response.status_code >= 200 and response.status_code < 300:
                return Response({
                    'status': 'success',
                    'message': f'Test webhook sent successfully. Response: {response.status_code}'
                })
            else:
                return Response({
                    'status': 'warning',
                    'message': f'Webhook sent but received non-success response: {response.status_code}'
                })
        
        except Exception as e:
            webhook.metadata.update({
                'last_test': {
                    'timestamp': timezone.now().isoformat(),
                    'event_type': event_type,
                    'error': str(e)
                }
            })
            webhook.save(update_fields=['metadata', 'updated_at'])
            
            return Response({
                'status': 'error',
                'message': f'Error sending webhook: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @swagger_auto_schema(
        operation_description="Get event types supported by webhooks",
        responses={
            200: openapi.Response(
                description="Event types",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'value': openapi.Schema(type=openapi.TYPE_STRING),
                            'label': openapi.Schema(type=openapi.TYPE_STRING),
                            'description': openapi.Schema(type=openapi.TYPE_STRING),
                        }
                    )
                )
            )
        }
    )
    @action(detail=False, methods=['get'])
    def event_types(self, request):
        """Get the list of event types supported by webhooks"""
        events = [
            {
                'value': 'message.sent',
                'label': 'Message Sent',
                'description': 'Triggered when a message is sent to the SMS gateway'
            },
            {
                'value': 'message.delivered',
                'label': 'Message Delivered',
                'description': 'Triggered when a message is delivered to the recipient'
            },
            {
                'value': 'message.failed',
                'label': 'Message Failed',
                'description': 'Triggered when a message fails to send or deliver'
            },
            {
                'value': 'campaign.started',
                'label': 'Campaign Started',
                'description': 'Triggered when a campaign starts sending messages'
            },
            {
                'value': 'campaign.completed',
                'label': 'Campaign Completed',
                'description': 'Triggered when a campaign completes sending all messages'
            },
            {
                'value': 'payment.successful',
                'label': 'Payment Successful',
                'description': 'Triggered when a payment is completed successfully'
            }
        ]
        
        return Response(events)


class LogoutView(APIView):
    """
    API endpoint for user logout - blacklists the refresh token.
    """
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Logout a user by blacklisting their refresh token",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh': openapi.Schema(type=openapi.TYPE_STRING, description='Refresh token'),
            },
            required=['refresh']
        ),
        responses={
            200: openapi.Response(
                description="Logout successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            400: "Bad request"
        }
    )
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)
                
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordRequestView(APIView):
    """
    API endpoint for requesting a password reset.
    """
    permission_classes = [AllowAny]
    
    @swagger_auto_schema(
        operation_description="Request password reset token",
        request_body=ResetPasswordRequestSerializer,
        responses={
            200: openapi.Response(
                description="Password reset email sent",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            400: "Bad request"
        }
    )
    def post(self, request):
        serializer = ResetPasswordRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                user = User.objects.get(email=email)
                
                # Check if email is verified
                if not user.email_verified:
                    return Response({
                        'message': 'Please verify your email before requesting a password reset.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Generate reset token
                token = generate_verification_token()
                user.verification_token = token
                user.token_created_at = timezone.now()
                user.token_expiration = timezone.now() + timedelta(hours=24)
                user.save()  # Make sure this save operation is successful
                
                # Add logging to verify token is saved
                logger.info(f"Password reset token generated for {email}: {token[:5]}...")
                
                # Send password reset email
                success, message = send_password_reset_email(user, token)
                
                if not success:
                    logger.error(f"Failed to send password reset email to {email}: {message}")
                else:
                    logger.info(f"Password reset email sent successfully to {email}")
                
                # For security, don't reveal if the email was sent successfully
                return Response({
                    'message': 'If an account with this email exists, a password reset link has been sent.'
                }, status=status.HTTP_200_OK)
            
            except User.DoesNotExist:
                # For security, don't reveal if user exists or not
                logger.info(f"Password reset requested for non-existent email: {email}")
                return Response({
                    'message': 'If an account with this email exists, a password reset link has been sent.'
                }, status=status.HTTP_200_OK)


class ResetPasswordConfirmView(APIView):
    """
    API endpoint for confirming password reset with token.
    """
    permission_classes = [AllowAny]
    
    @method_decorator(sensitive_post_parameters('new_password', 'confirm_password'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Confirm password reset with token",
        request_body=ResetPasswordConfirmSerializer,
        responses={
            200: openapi.Response(
                description="Password reset successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            400: "Invalid token or Bad request"
        }
    )
    def post(self, request):
        serializer = ResetPasswordConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']
            
            # Add debug logging
            logger.info(f"Attempting password reset with token: {token[:5]}...")
            
            try:
                # Try to find user with this token
                user = User.objects.get(verification_token=token)
                
                # Check if token is expired
                if not is_token_valid(user):
                    logger.warning(f"Expired token used for password reset: {token[:5]}...")
                    return Response({
                        'message': 'Password reset token has expired. Please request a new one.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                logger.info(f"Valid password reset token for user: {user.email}")
                
                # Set new password
                user.set_password(new_password)
                
                # Clear the token
                user.verification_token = None
                user.token_created_at = None
                user.token_expiration = None
                user.save()
                
                logger.info(f"Password reset successful for user: {user.email}")
                
                return Response({
                    'message': 'Password has been reset successfully.'
                }, status=status.HTTP_200_OK)
                
            except User.DoesNotExist:
                logger.warning(f"Invalid token used for password reset: {token[:5]}...")
                return Response({
                    'message': 'Invalid password reset token.'
                }, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(UpdateAPIView):
    """
    API endpoint for changing user password.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer
    
    @method_decorator(sensitive_post_parameters('old_password', 'new_password', 'confirm_password'))
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
    
    def get_object(self):
        return self.request.user
    
    @swagger_auto_schema(
        operation_description="Change user password",
        request_body=ChangePasswordSerializer,
        responses={
            200: openapi.Response(
                description="Password updated successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            400: "Wrong password or Bad request"
        }
    )
    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(data=request.data)
        
        if serializer.is_valid():
            # Check old password
            if not user.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            
            # Set new password
            user.set_password(serializer.data.get("new_password"))
            user.save()
            
            return Response({
                'message': 'Password updated successfully'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(RetrieveUpdateAPIView):
    """
    API endpoint for retrieving and updating user profile.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileUpdateSerializer
    
    def get_object(self):
        return self.request.user
    
    @swagger_auto_schema(
        operation_description="Get user profile",
        responses={
            200: UserProfileUpdateSerializer,
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Update user profile",
        request_body=UserProfileUpdateSerializer,
        responses={
            200: openapi.Response(
                description="Profile updated successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'email_changed': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'profile': UserProfileUpdateSerializer,
                    }
                )
            ),
            400: "Bad request"
        }
    )
    def update(self, request, *args, **kwargs):
        # Store current email to check if it changes
        current_email = request.user.email
        
        # Process the update
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        # Check if email was changed
        email_changed = current_email != instance.email
        
        if email_changed:
            return Response({
                'message': 'Profile updated successfully. Please verify your new email address.',
                'email_changed': True,
                'profile': serializer.data
            })
        else:
            return Response({
                'message': 'Profile updated successfully.',
                'email_changed': False,
                'profile': serializer.data
            })


class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited by admins.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]

    @swagger_auto_schema(
        operation_description="Get current user information",
        responses={
            200: UserSerializer
        }
    )
    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def me(self, request):
        """
        Return the authenticated user's details
        """
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)


class ContactGroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows contact groups to be viewed or edited.
    """
    queryset = ContactGroup.objects.all()
    serializer_class = ContactGroupSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at', 'updated_at']
    ordering = ['name']

    def get_queryset(self):
        """
        This view returns contact groups for the currently authenticated user.
        """
        return ContactGroup.objects.filter(user=self.request.user)

    @swagger_auto_schema(
        operation_description="List all contact groups belonging to the authenticated user"
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Create a new contact group"
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Retrieve a specific contact group by ID"
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Update a specific contact group"
    )
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Delete a specific contact group"
    )
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
        
    @action(detail=True, methods=['get'])
    def contacts(self, request, pk=None):
        """
        List all contacts in a specific group
        """
        group = self.get_object()
        contacts = Contact.objects.filter(group=group)
        serializer = ContactSerializer(contacts, many=True, context={'request': request})
        return Response(serializer.data)
    
    @swagger_auto_schema(
        operation_description="Create a new contact group"
    )
    @action(detail=False, methods=['post'], url_path='new-group')
    def new_group(self, request):
        """
        Create a new contact group with validation
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ContactViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows contacts to be viewed or edited.
    """
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'phone_number']
    ordering_fields = ['name', 'phone_number', 'created_at', 'last_message_sent']
    ordering = ['name']

    def get_queryset(self):
        """
        This view returns contacts in groups owned by the currently authenticated user.
        Filter by group if provided in query params.
        """
        queryset = Contact.objects.filter(group__user=self.request.user)
        
        # Filter by group if provided
        group_id = self.request.query_params.get('group')
        if group_id:
            queryset = queryset.filter(group_id=group_id)
            
        return queryset

    @swagger_auto_schema(
        operation_description="List all contacts in user's groups"
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Create a new contact in one of user's groups"
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Retrieve a specific contact by ID"
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Update a specific contact"
    )
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Delete a specific contact"
    )
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
        
    @swagger_auto_schema(
        operation_description="Import contacts in bulk"
    )
    @action(detail=False, methods=['post'])
    def import_contacts(self, request):
        """
        Import multiple contacts at once
        """
        group_id = request.data.get('group')
        contacts_data = request.data.get('contacts', [])
        
        if not group_id:
            return Response({"error": "Group ID is required"}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            group = ContactGroup.objects.get(id=group_id, user=request.user)
        except ContactGroup.DoesNotExist:
            return Response({"error": "Group not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Process each contact
        created_contacts = []
        errors = []
        
        for i, contact_data in enumerate(contacts_data):
            # Add group to each contact
            contact_data['group'] = group_id
            
            # Validate and create the contact
            serializer = self.get_serializer(data=contact_data)
            if serializer.is_valid():
                contact = serializer.save()
                created_contacts.append(serializer.data)
            else:
                # Add the index of the failed contact for reference
                errors.append({
                    "index": i,
                    "data": contact_data,
                    "errors": serializer.errors
                })
        
        return Response({
            "created": len(created_contacts),
            "failed": len(errors),
            "contacts": created_contacts,
            "errors": errors
        })
    
    @swagger_auto_schema(
        operation_description="Export contacts from a group"
    )
    @action(detail=False, methods=['get'])
    def export(self, request):
        """
        Export contacts from a group
        """
        group_id = request.query_params.get('group')
        if not group_id:
            return Response({"error": "Group ID is required"}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            group = ContactGroup.objects.get(id=group_id, user=request.user)
        except ContactGroup.DoesNotExist:
            return Response({"error": "Group not found"}, status=status.HTTP_404_NOT_FOUND)
            
        contacts = Contact.objects.filter(group=group)
        serializer = self.get_serializer(contacts, many=True)
        
        return Response({
            "group": group.name,
            "count": contacts.count(),
            "contacts": serializer.data
        })
        
    @swagger_auto_schema(
        operation_description="Add a new contact"
    )
    @action(detail=False, methods=['post'])
    def add_contact(self, request):
        """
        Add a new contact with validation
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CampaignViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing SMS campaigns.
    """
    queryset = Campaign.objects.all()
    serializer_class = CampaignSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Filter campaigns to show only those belonging to the current user"""
        return self.queryset.filter(user=self.request.user)

    def perform_create(self, serializer):
        """Set the user when creating a new campaign"""
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        """Start a campaign"""
        campaign = self.get_object()
        
        # Check if campaign can be started
        if campaign.status != Campaign.Status.DRAFT:
            return Response(
                {"error": "Campaign can only be started from draft status"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if campaign.scheduled_time and campaign.scheduled_time > timezone.now():
            # Schedule the campaign for later
            campaign.status = Campaign.Status.SCHEDULED
            campaign.save()
            send_campaign_messages.apply_async(
                args=[campaign.id],
                eta=campaign.scheduled_time
            )
            return Response({"message": "Campaign scheduled successfully"})
        else:
            # Start the campaign immediately
            campaign.status = Campaign.Status.PROCESSING
            campaign.save()
            send_campaign_messages.delay(campaign.id)
            return Response({"message": "Campaign started successfully"})

    @action(detail=True, methods=['post'])
    def pause(self, request, pk=None):
        """Pause a running campaign"""
        campaign = self.get_object()
        
        if campaign.status not in [Campaign.Status.PROCESSING, Campaign.Status.SCHEDULED]:
            return Response(
                {"error": "Only processing or scheduled campaigns can be paused"},
                status=status.HTTP_400_BAD_REQUEST
            )

        campaign.status = Campaign.Status.PAUSED
        campaign.save()
        return Response({"message": "Campaign paused successfully"})

    @action(detail=True, methods=['post'])
    def resume(self, request, pk=None):
        """Resume a paused campaign"""
        campaign = self.get_object()
        
        if campaign.status != Campaign.Status.PAUSED:
            return Response(
                {"error": "Only paused campaigns can be resumed"},
                status=status.HTTP_400_BAD_REQUEST
            )

        campaign.status = Campaign.Status.PROCESSING
        campaign.save()
        send_campaign_messages.delay(campaign.id)
        return Response({"message": "Campaign resumed successfully"})

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a campaign"""
        campaign = self.get_object()
        
        if campaign.status in [Campaign.Status.COMPLETED, Campaign.Status.CANCELLED]:
            return Response(
                {"error": "Cannot cancel completed or already cancelled campaigns"},
                status=status.HTTP_400_BAD_REQUEST
            )

        campaign.status = Campaign.Status.CANCELLED
        campaign.save()
        return Response({"message": "Campaign cancelled successfully"})

    @action(detail=True, methods=['get'])
    def statistics(self, request, pk=None):
        """Get campaign statistics"""
        campaign = self.get_object()
        messages = SMSMessage.objects.filter(campaign=campaign)
        
        stats = {
            'total_messages': messages.count(),
            'delivered': messages.filter(status=SMSMessage.Status.DELIVERED).count(),
            'failed': messages.filter(status=SMSMessage.Status.FAILED).count(),
            'pending': messages.filter(status=SMSMessage.Status.PENDING).count(),
            'sent': messages.filter(status=SMSMessage.Status.SENT).count(),
        }
        
        return Response(stats)

    @action(detail=True, methods=['get'])
    def messages(self, request, pk=None):
        """Get all messages in a campaign"""
        campaign = self.get_object()
        messages = SMSMessage.objects.filter(campaign=campaign)
        
        # Add filtering
        status = request.query_params.get('status')
        if status:
            messages = messages.filter(status=status)

        # Add search
        search = request.query_params.get('search')
        if search:
            messages = messages.filter(
                Q(recipient__icontains=search) |
                Q(message_id__icontains=search)
            )

        serializer = SMSMessageSerializer(messages, many=True)
        return Response(serializer.data)


class SMSMessageViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows SMS messages to be viewed or edited.
    """
    queryset = SMSMessage.objects.all()  # Add default queryset
    serializer_class = SMSMessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """
        This view returns messages for the currently authenticated user.
        """
        return SMSMessage.objects.filter(user=self.request.user)

    @swagger_auto_schema(
        operation_description="Send a quick SMS message",
        request_body=SMSMessageSerializer,
        responses={
            201: SMSMessageSerializer,
            400: "Bad request"
        }
    )
    @action(detail=False, methods=['post'])
    def quick_send(self, request):
        """Send a quick SMS message without creating a campaign"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            # Add the current user
            serializer.validated_data['user'] = request.user
            
            # Calculate message segments (for token deduction)
            message_content = serializer.validated_data.get('content', '')
            segments = max(1, len(message_content) // 160 + (1 if len(message_content) % 160 > 0 else 0))
            serializer.validated_data['segments'] = segments
            
            # Check if user has enough tokens
            user = request.user
            if user.tokens_balance < segments:
                return Response(
                    {"detail": "Insufficient tokens. Please add tokens to your account."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create the message
            message = serializer.save(status='queued')
            
            # Use Celery to send the message asynchronously
            from .tasks import send_single_sms
            send_single_sms.delay(str(message.id))
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response(
                {"detail": f"Error sending message: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @swagger_auto_schema(
        operation_description="Africa's Talking delivery report callback endpoint",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'id': openapi.Schema(type=openapi.TYPE_STRING),
                'phoneNumber': openapi.Schema(type=openapi.TYPE_STRING),
                'status': openapi.Schema(type=openapi.TYPE_STRING),
                'networkCode': openapi.Schema(type=openapi.TYPE_STRING),
                'failureReason': openapi.Schema(type=openapi.TYPE_STRING, description='Reason for failure if status is Failed'),
            }
        ),
        responses={
            200: openapi.Response(
                description="Callback processed successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            )
        }
    )
    @action(detail=False, methods=['post'], permission_classes=[AllowAny], url_path='delivery-callback')
    def delivery_callback(self, request):
        """Handle delivery callbacks from Africa's Talking"""
        try:
            # Log the callback data for debugging
            logger.info(f"Africa's Talking delivery callback received: {request.data}")
            
            # Get message ID from the callback
            message_id = request.data.get('id')
            phone_number = request.data.get('phoneNumber')
            status = request.data.get('status')
            failure_reason = request.data.get('failureReason')
            
            if not message_id or not status:
                return Response({"status": "Missing required parameters"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Map Africa's Talking status to our internal statuses
            status_mapping = {
                'Success': 'delivered',
                'Sent': 'sent',
                'Failed': 'failed',
                'Rejected': 'rejected',
                'Buffered': 'queued',
            }
            
            internal_status = status_mapping.get(status, 'unknown')
            
            # Find the message with this message_id
            try:
                message = SMSMessage.objects.get(message_id=message_id)
            except SMSMessage.DoesNotExist:
                # Try to find message by recipient phone number if message_id doesn't match
                if phone_number:
                    messages = SMSMessage.objects.filter(
                        recipient=phone_number,
                        delivery_status__in=['pending', 'queued', 'sending', 'sent']
                    ).order_by('-created_at')
                    
                    if messages.exists():
                        message = messages.first()
                    else:
                        return Response({"status": "Message not found"}, status=status.HTTP_404_NOT_FOUND)
                else:
                    return Response({"status": "Message not found"}, status=status.HTTP_404_NOT_FOUND)
            
            # Update message delivery status
            message.delivery_status = internal_status
            
            # If delivered, set delivery time
            if internal_status == 'delivered' and not message.delivery_time:
                message.delivery_time = timezone.now()
            
            # Add failure reason if available
            if failure_reason:
                message.error_message = failure_reason
            
            # Update metadata
            message.metadata.update({
                'callback_data': request.data,
                'status_updated_at': timezone.now().isoformat()
            })
            
            message.save(update_fields=[
                'delivery_status', 
                'delivery_time', 
                'error_message', 
                'metadata', 
                'updated_at'
            ])
            
            # Send webhook event for status update
            from utils.webhooks import send_event_to_user_webhooks
            
            event_type = f"message.{internal_status}"
            send_event_to_user_webhooks(
                user_id=str(message.user.id),
                event_type=event_type,
                data={
                    'message_id': str(message.id),
                    'recipient': message.recipient,
                    'status': message.status,
                    'delivery_status': message.delivery_status,
                    'campaign_id': str(message.campaign.id) if message.campaign else None,
                    'delivered_at': message.delivery_time.isoformat() if message.delivery_time else None,
                    'error': failure_reason if failure_reason else None
                }
            )
            
            return Response({"status": "Delivery status updated successfully"})
            
        except Exception as e:
            logger.error(f"Error processing Africa's Talking delivery callback: {str(e)}")
            return Response(
                {"status": f"Error: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PaymentViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows payments to be viewed or created.
    """
    queryset = Payment.objects.all()
    serializer_class = PaymentSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Return only the authenticated user's payments"""
        return Payment.objects.filter(user=self.request.user)
    
    @swagger_auto_schema(
        operation_description="List all payments made by the authenticated user"
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Create a new payment request",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'amount': openapi.Schema(type=openapi.TYPE_NUMBER, description='Payment amount'),
                'payment_method': openapi.Schema(type=openapi.TYPE_STRING, description='Payment method (mpesa)'),
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='Phone number for M-Pesa'),
            },
            required=['amount', 'payment_method']
        ),
        responses={
            201: openapi.Response(
                description="Payment initiated",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'id': openapi.Schema(type=openapi.TYPE_STRING),
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            400: "Bad request"
        }
    )
    def create(self, request, *args, **kwargs):
        """Create a new payment request"""
        
        # Validate required fields
        amount = request.data.get('amount')
        payment_method = request.data.get('payment_method', 'mpesa')
        
        if not amount:
            return Response(
                {"detail": "Amount is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            amount = float(amount)
            if amount <= 0:
                return Response(
                    {"detail": "Amount must be greater than zero."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except (ValueError, TypeError):
            return Response(
                {"detail": "Invalid amount."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create a payment record with pending status
        payment = Payment.objects.create(
            user=request.user,
            amount=amount,
            status='pending',
            metadata={
                'payment_method': payment_method,
                'initiated_at': timezone.now().isoformat()
            }
        )
        
        # Handle M-Pesa payment
        if payment_method.lower() == 'mpesa':
            phone_number = request.data.get('phone_number')
            
            if not phone_number:
                # Use user's phone number if not provided
                phone_number = request.user.phone_number
            
            if not phone_number:
                payment.status = 'failed'
                payment.metadata.update({
                    'error': 'Phone number is required for M-Pesa payments.',
                    'failed_at': timezone.now().isoformat()
                })
                payment.save(update_fields=['status', 'metadata', 'updated_at'])
                
                return Response(
                    {"detail": "Phone number is required for M-Pesa payments."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Initialize M-Pesa payment
            from utils.mpesa import MPesaClient
            mpesa = MPesaClient()
            
            account_reference = f"GDA-{request.user.id}"
            transaction_desc = f"Payment for SMS tokens"
            
            result = mpesa.initiate_stk_push(
                phone_number=phone_number,
                amount=amount,
                account_reference=account_reference,
                transaction_desc=transaction_desc
            )
            
            if result.get('status') == 'success':
                # Update payment record with M-Pesa data
                payment.metadata.update({
                    'checkout_request_id': result.get('checkout_request_id'),
                    'mpesa_response': result.get('response'),
                    'stk_push_at': timezone.now().isoformat()
                })
                payment.save(update_fields=['metadata', 'updated_at'])
                
                # Add tokens to user's balance based on payment amount
                # Simplified conversion: 1 KES = 1 token
                tokens_to_add = int(payment.amount)
                payment.user.tokens_balance += tokens_to_add
                payment.user.save(update_fields=['tokens_balance'])
                
                payment.metadata.update({
                    'tokens_added': tokens_to_add,
                    'completed_at': timezone.now().isoformat()
                })
                
                payment.save(update_fields=['status', 'payment_date', 'metadata', 'updated_at'])
                
                # Send webhook event for successful payment
                from utils.webhooks import send_event_to_user_webhooks
                send_event_to_user_webhooks(
                    user_id=str(payment.user.id),
                    event_type='payment.successful',
                    data={
                        'payment_id': str(payment.id),
                        'amount': float(payment.amount),
                        'tokens_added': tokens_to_add,
                        'payment_method': payment.metadata.get('payment_method', 'mpesa'),
                        'completed_at': timezone.now().isoformat()
                    }
                )
                
                return Response({
                    'id': str(payment.id),
                    'status': 'pending',
                    'message': 'M-Pesa STK push sent. Please check your phone and enter PIN.',
                    'checkout_request_id': result.get('checkout_request_id')
                }, status=status.HTTP_201_CREATED)
            else:
                # Update payment record with error
                payment.status = 'failed'
                payment.metadata.update({
                    'error': result.get('message'),
                    'mpesa_response': result.get('response'),
                    'failed_at': timezone.now().isoformat()
                })
                payment.save(update_fields=['status', 'metadata', 'updated_at'])
                
                return Response({
                    'id': str(payment.id),
                    'status': 'failed',
                    'message': result.get('message')
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Add other payment methods here as needed
        
        return Response({
            'id': str(payment.id),
            'status': 'pending',
            'message': f'Payment initiated with {payment_method}.'
        }, status=status.HTTP_201_CREATED)
    
    @swagger_auto_schema(
        operation_description="Check the status of a payment",
        responses={
            200: openapi.Response(
                description="Payment status",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'id': openapi.Schema(type=openapi.TYPE_STRING),
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            404: "Payment not found"
        }
    )
    @action(detail=True, methods=['get'])
    def check_status(self, request, pk=None):
        """Check the status of a payment"""
        try:
            payment = self.get_object()
            
            # If payment is already completed or failed, just return the status
            if payment.status in ['completed', 'failed', 'refunded']:
                return Response({
                    'id': str(payment.id),
                    'status': payment.status,
                    'message': f'Payment {payment.status}.'
                })
            
            # For M-Pesa payments, check the status via API
            if payment.metadata.get('payment_method') == 'mpesa' and payment.metadata.get('checkout_request_id'):
                from utils.mpesa import MPesaClient
                mpesa = MPesaClient()
                
                result = mpesa.query_stk_status(payment.metadata.get('checkout_request_id'))
                
                payment.metadata.update({
                    'status_check_response': result,
                    'status_checked_at': timezone.now().isoformat()
                })
                
                if result.get('status') == 'success':
                    mpesa_response = result.get('response', {})
                    result_code = mpesa_response.get('ResultCode')
                    result_desc = mpesa_response.get('ResultDesc', '')
                    
                    # Import webhook utility
                    from utils.webhooks import send_event_to_user_webhooks
                    
                    if result_code == 0:
                        # Payment successful
                        payment.status = 'completed'
                        payment.payment_date = timezone.now()
                        
                        # Add tokens to user's balance based on payment amount
                        # Simplified conversion: 1 KES = 1 token
                        tokens_to_add = int(payment.amount)
                        payment.user.tokens_balance += tokens_to_add
                        payment.user.save(update_fields=['tokens_balance'])
                        
                        payment.metadata.update({
                            'tokens_added': tokens_to_add,
                            'completed_at': timezone.now().isoformat(),
                            'result_desc': result_desc
                        })
                        
                        payment.save(update_fields=['status', 'payment_date', 'metadata', 'updated_at'])
                        
                        # Send webhook event for successful payment
                        send_event_to_user_webhooks(
                            user_id=str(payment.user.id),
                            event_type='payment.successful',
                            data={
                                'payment_id': str(payment.id),
                                'amount': float(payment.amount),
                                'tokens_added': tokens_to_add,
                                'payment_method': payment.metadata.get('payment_method', 'mpesa'),
                                'completed_at': timezone.now().isoformat(),
                                'result_desc': result_desc
                            }
                        )
                        
                        return Response({
                            'id': str(payment.id),
                            'status': 'completed',
                            'message': 'Payment completed successfully.',
                            'tokens_added': tokens_to_add
                        })
                    elif result_code == 1032:
                        # Transaction cancelled by user
                        payment.status = 'failed'
                        payment.metadata.update({
                            'error': 'Transaction was cancelled by the user.',
                            'error_code': result_code,
                            'cancelled_at': timezone.now().isoformat(),
                            'result_desc': result_desc
                        })
                        payment.save(update_fields=['status', 'metadata', 'updated_at'])
                        
                        # Send webhook event for cancelled payment
                        send_event_to_user_webhooks(
                            user_id=str(payment.user.id),
                            event_type='payment.cancelled',
                            data={
                                'payment_id': str(payment.id),
                                'amount': float(payment.amount),
                                'payment_method': payment.metadata.get('payment_method', 'mpesa'),
                                'cancelled_at': timezone.now().isoformat(),
                                'result_desc': result_desc,
                                'error_code': result_code
                            }
                        )
                        
                        return Response({
                            'id': str(payment.id),
                            'status': 'cancelled',
                            'message': 'Transaction was cancelled by the user.'
                        })
                    elif result_code == 1037:
                        # Timeout 
                        payment.status = 'failed'
                        payment.metadata.update({
                            'error': 'Transaction timed out.',
                            'error_code': result_code,
                            'failed_at': timezone.now().isoformat(),
                            'result_desc': result_desc
                        })
                        payment.save(update_fields=['status', 'metadata', 'updated_at'])
                        
                        # Send webhook event for failed payment
                        send_event_to_user_webhooks(
                            user_id=str(payment.user.id),
                            event_type='payment.failed',
                            data={
                                'payment_id': str(payment.id),
                                'amount': float(payment.amount),
                                'payment_method': payment.metadata.get('payment_method', 'mpesa'),
                                'failed_at': timezone.now().isoformat(),
                                'result_desc': result_desc,
                                'error_code': result_code
                            }
                        )
                        
                        return Response({
                            'id': str(payment.id),
                            'status': 'failed',
                            'message': 'Transaction timed out.'
                        })
                    else:
                        # Other error
                        payment.status = 'failed'
                        payment.metadata.update({
                            'error': result_desc,
                            'error_code': result_code,
                            'failed_at': timezone.now().isoformat()
                        })
                        payment.save(update_fields=['status', 'metadata', 'updated_at'])
                        
                        # Send webhook event for failed payment
                        send_event_to_user_webhooks(
                            user_id=str(payment.user.id),
                            event_type='payment.failed',
                            data={
                                'payment_id': str(payment.id),
                                'amount': float(payment.amount),
                                'payment_method': payment.metadata.get('payment_method', 'mpesa'),
                                'failed_at': timezone.now().isoformat(),
                                'result_desc': result_desc,
                                'error_code': result_code
                            }
                        )
                        
                        return Response({
                            'id': str(payment.id),
                            'status': 'failed',
                            'message': result_desc
                        })
                
            # For other payment methods or if status check fails
            payment.save(update_fields=['metadata', 'updated_at'])
            return Response({
                'id': str(payment.id),
                'status': payment.status,
                'message': 'Payment status is still pending.'
            })
            
        except Exception as e:
            logger.error(f"Error checking payment status: {str(e)}")
            return Response(
                {"detail": f"Error checking payment status: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        operation_description="M-Pesa callback endpoint",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'Body': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'stkCallback': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'MerchantRequestID': openapi.Schema(type=openapi.TYPE_STRING),
                                'CheckoutRequestID': openapi.Schema(type=openapi.TYPE_STRING),
                                'ResultCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'ResultDesc': openapi.Schema(type=openapi.TYPE_STRING),
                            }
                        )
                    }
                )
            }
        ),
        responses={
            200: openapi.Response(
                description="Callback received",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            )
        }
    )
    @action(detail=False, methods=['post'], permission_classes=[AllowAny], url_path='callback')
    def mpesa_callback(self, request):
        """Handle M-Pesa callback"""
        try:
            # Log the callback data for debugging
            logger.info(f"M-Pesa callback received: {request.data}")
            
            # Extract relevant data from the callback
            callback_data = request.data.get('Body', {}).get('stkCallback', {})
            checkout_request_id = callback_data.get('CheckoutRequestID')
            result_code = callback_data.get('ResultCode')
            result_desc = callback_data.get('ResultDesc')
            
            if not checkout_request_id:
                return Response({"status": "Invalid callback data"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Find the payment with this checkout_request_id
            try:
                payment = Payment.objects.get(metadata__checkout_request_id=checkout_request_id)
            except Payment.DoesNotExist:
                return Response({"status": "Payment not found"}, status=status.HTTP_404_NOT_FOUND)
            
            # Import webhook utility
            from utils.webhooks import send_event_to_user_webhooks
            
            # Update payment based on result code
            if result_code == 0:
                # Payment successful
                payment.status = 'completed'
                payment.payment_date = timezone.now()
                
                # Add tokens to user's balance
                tokens_to_add = int(payment.amount)  # Simplified: 1 KES = 1 token
                payment.user.tokens_balance += tokens_to_add
                payment.user.save(update_fields=['tokens_balance'])
                
                payment.metadata.update({
                    'callback_data': callback_data,
                    'tokens_added': tokens_to_add,
                    'completed_at': timezone.now().isoformat()
                })
                
                payment.save(update_fields=['status', 'payment_date', 'metadata', 'updated_at'])
                
                # Send webhook event for successful payment
                send_event_to_user_webhooks(
                    user_id=str(payment.user.id),
                    event_type='payment.successful',
                    data={
                        'payment_id': str(payment.id),
                        'amount': float(payment.amount),
                        'tokens_added': tokens_to_add,
                        'payment_method': payment.metadata.get('payment_method', 'mpesa'),
                        'completed_at': timezone.now().isoformat(),
                        'result_desc': result_desc
                    }
                )
            
            elif result_code == 1032:  
                # Transaction cancelled by user
                payment.status = 'failed'
                payment.metadata.update({
                    'callback_data': callback_data,
                    'error': result_desc,
                    'error_code': result_code,
                    'cancelled_at': timezone.now().isoformat()
                })
                payment.save(update_fields=['status', 'metadata', 'updated_at'])
                
                # Send webhook event for cancelled payment
                send_event_to_user_webhooks(
                    user_id=str(payment.user.id),
                    event_type='payment.cancelled',
                    data={
                        'payment_id': str(payment.id),
                        'amount': float(payment.amount),
                        'payment_method': payment.metadata.get('payment_method', 'mpesa'),
                        'cancelled_at': timezone.now().isoformat(),
                        'result_desc': result_desc,
                        'error_code': result_code
                    }
                )
            
            else:
                # Payment failed
                payment.status = 'failed'
                payment.metadata.update({
                    'callback_data': callback_data,
                    'error': result_desc,
                    'error_code': result_code,
                    'failed_at': timezone.now().isoformat()
                })
                payment.save(update_fields=['status', 'metadata', 'updated_at'])
                
                # Send webhook event for failed payment
                send_event_to_user_webhooks(
                    user_id=str(payment.user.id),
                    event_type='payment.failed',
                    data={
                        'payment_id': str(payment.id),
                        'amount': float(payment.amount),
                        'payment_method': payment.metadata.get('payment_method', 'mpesa'),
                        'failed_at': timezone.now().isoformat(),
                        'result_desc': result_desc,
                        'error_code': result_code
                    }
                )
            
            return Response({"status": "Callback processed successfully"})
            
        except Exception as e:
            logger.error(f"Error processing M-Pesa callback: {str(e)}")
            return Response(
                {"status": f"Error: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class MessageTemplateViewSet(viewsets.ModelViewSet):
    """ViewSet for managing message templates"""
    serializer_class = MessageTemplateSerializer
    queryset = MessageTemplate.objects.all()
    template_service = TemplateVerificationService()

    def get_queryset(self):
        """Filter queryset for current user"""
        return self.queryset.filter(user=self.request.user)

    def perform_create(self, serializer):
        """Create new template and verify content"""
        template = serializer.save(user=self.request.user)
        self.template_service.process_template(template)

    def perform_update(self, serializer):
        """Update template and re-verify content"""
        template = serializer.save()
        self.template_service.process_template(template)

    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        """Manually trigger template verification"""
        template = self.get_object()
        verified_template = self.template_service.process_template(template)
        
        return Response({
            'status': verified_template.verification_status,
            'rejection_reason': verified_template.rejection_reason,
            'metadata': verified_template.metadata.get('verification_metadata', {})
        })

    @action(detail=False, methods=['get'])
    def categories(self, request):
        """Get available template categories"""
        return Response({
            'categories': [
                {'value': choice[0], 'label': choice[1]}
                for choice in MessageTemplate.TemplateCategory.choices
            ]
        })

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get template usage statistics"""
        templates = self.get_queryset()
        
        stats = {
            'total_count': templates.count(),
            'by_status': {
                status: templates.filter(verification_status=status).count()
                for status, _ in MessageTemplate.VerificationStatus.choices
            },
            'by_category': {
                category: templates.filter(category=category).count()
                for category, _ in MessageTemplate.TemplateCategory.choices
            },
            'most_used': templates.order_by('-usage_count')[:5].values(
                'name', 'category', 'usage_count'
            )
        }
        
        return Response(stats)