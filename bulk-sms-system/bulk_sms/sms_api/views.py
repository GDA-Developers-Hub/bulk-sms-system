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
from .models import SMSTemplate, ContactGroup, Contact
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
    SMSCampaignSerializer, PaymentSerializer, SMSTemplateSerializer,
    WebhookEndpointSerializer, SMSMessageSerializer, LoginSerializer
)
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

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
    API endpoint for managing SMS templates
    
    Provides CRUD operations:
    - list: GET /smstemplates/
    - retrieve: GET /smstemplates/{id}/
    - create: POST /smstemplates/
    - update: PUT /smstemplates/{id}/
    - partial_update: PATCH /smstemplates/{id}/
    - destroy: DELETE /smstemplates/{id}/
    
    Additional actions:
    - mark_used: POST /smstemplates/{id}/mark_used/
    - categories: GET /smstemplates/categories/
    """
    serializer_class = SMSTemplateSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'content', 'category']
    ordering_fields = ['name', 'category', 'created_at', 'updated_at', 'last_used']
    ordering = ['-created_at']
    
    def get_queryset(self):
        """Return templates owned by the current user"""
        return SMSTemplate.objects.filter(user=self.request.user)
    
    def list(self, request, *args, **kwargs):
        """
        List all SMS templates for the current user
        GET /smstemplates/
        """
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
            
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve a specific SMS template by ID
        GET /smstemplates/{id}/
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)
    
    def create(self, request, *args, **kwargs):
        """
        Create a new SMS template
        POST /smstemplates/
        """
        # Add current user to the data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user)
        
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
    
    def update(self, request, *args, **kwargs):
        """
        Update an existing SMS template (full update)
        PUT /smstemplates/{id}/
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}
            
        return Response(serializer.data)
    
    def partial_update(self, request, *args, **kwargs):
        """
        Partially update an SMS template
        PATCH /smstemplates/{id}/
        """
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)
    
    def destroy(self, request, *args, **kwargs):
        """
        Delete an SMS template
        DELETE /smstemplates/{id}/
        """
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=True, methods=['post'])
    def mark_used(self, request, pk=None):
        """
        Mark a template as used by updating last_used timestamp
        POST /smstemplates/{id}/mark_used/
        """
        template = self.get_object()
        template.last_used = timezone.now()
        template.save(update_fields=['last_used'])
        return Response({'status': 'template marked as used'})
    
    @action(detail=False, methods=['get'])
    def categories(self, request):
        """
        Return available template categories
        GET /smstemplates/categories/
        """
        categories = [{"value": key, "label": value} for key, value in SMSTemplate.CATEGORY_CHOICES]
        return Response(categories)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """
        Get statistics about templates
        GET /smstemplates/stats/
        """
        user_templates = self.get_queryset()
        stats = {
            'total_count': user_templates.count(),
            'by_category': {},
            'recently_used': user_templates.exclude(last_used=None).order_by('-last_used')[:5].values('id', 'name', 'last_used'),
            'recently_created': user_templates.order_by('-created_at')[:5].values('id', 'name', 'created_at')
        }
        
        # Count by category
        for key, label in SMSTemplate.CATEGORY_CHOICES:
            stats['by_category'][key] = user_templates.filter(category=key).count()
            
        return Response(stats)


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


class SMSCampaignViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows SMS campaigns to be created, viewed, edited, and sent.
    """
    serializer_class = SMSCampaignSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'message', 'sender_id', 'status']
    ordering_fields = ['name', 'created_at', 'updated_at', 'scheduled_time', 'status']
    ordering = ['-created_at']

    def get_queryset(self):
        """
        This view returns campaigns for the currently authenticated user.
        Filter by status if provided in query params.
        """
        queryset = SMSCampaign.objects.filter(user=self.request.user)
        
        # Filter by status if provided
        status = self.request.query_params.get('status')
        if status:
            queryset = queryset.filter(status=status)
            
        # Filter by type if provided
        campaign_type = self.request.query_params.get('type')
        if campaign_type:
            queryset = queryset.filter(type=campaign_type)
            
        return queryset

    @swagger_auto_schema(
        operation_description="List all SMS campaigns belonging to the authenticated user"
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Create a new SMS campaign"
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Retrieve a specific SMS campaign by ID"
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Update a specific SMS campaign"
    )
    def update(self, request, *args, **kwargs):
        campaign = self.get_object()
        
        # Don't allow updates if campaign is not in draft status
        if campaign.status not in ['draft', 'scheduled']:
            return Response(
                {"error": f"Cannot update campaign in '{campaign.status}' status. Only draft or scheduled campaigns can be updated."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        return super().update(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Delete a specific SMS campaign"
    )
    def destroy(self, request, *args, **kwargs):
        campaign = self.get_object()
        
        # Don't allow deletion if campaign is sending or processing
        if campaign.status in ['sending', 'processing']:
            return Response(
                {"error": f"Cannot delete campaign in '{campaign.status}' status."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=['post'])
    def send(self, request, pk=None):
        """
        Initiate sending of a draft campaign
        """
        campaign = self.get_object()
        if campaign.status != 'draft':
            return Response(
                {"error": "Only draft campaigns can be sent"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Here you would implement the logic to send the campaign
        # This is a placeholder for now
        campaign.status = 'sending'
        campaign.save()
        
        return Response({"status": "Campaign sending initiated"})
        
    @swagger_auto_schema(
        operation_description="Cancel a scheduled SMS campaign",
        responses={
            200: openapi.Response(
                description="Campaign cancelled successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            400: "Campaign not in scheduled status"
        }
    )
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """
        Cancel a scheduled campaign
        """
        campaign = self.get_object()
        
        if campaign.status != 'scheduled':
            return Response(
                {"error": "Only scheduled campaigns can be cancelled"},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        campaign.status = 'cancelled'
        campaign.save()
        
        return Response({
            "status": "success",
            "message": "Campaign cancelled successfully"
        })
    
    @swagger_auto_schema(
        operation_description="Get statistics for a specific campaign",
        responses={
            200: openapi.Response(
                description="Campaign statistics",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'campaign_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'campaign_name': openapi.Schema(type=openapi.TYPE_STRING),
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                        'total_recipients': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'messages': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'total': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'queued': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'sent': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'delivered': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'failed': openapi.Schema(type=openapi.TYPE_INTEGER),
                            }
                        ),
                        'delivery_rate': openapi.Schema(type=openapi.TYPE_NUMBER),
                    }
                )
            )
        }
    )
    @action(detail=True, methods=['get'])
    def stats(self, request, pk=None):
        """
        Get statistics for a campaign
        """
        campaign = self.get_object()
        
        # Get message statistics
        messages = SMSMessage.objects.filter(campaign=campaign)
        total_messages = messages.count()
        
        delivered = messages.filter(delivery_status='delivered').count()
        failed = messages.filter(delivery_status__in=['failed', 'rejected', 'expired']).count()
        queued = messages.filter(status='queued').count()
        sent = messages.filter(status='sent').count()
        
        # Calculate delivery rate
        delivery_rate = (delivered / total_messages * 100) if total_messages > 0 else 0
        
        return Response({
            'campaign_id': str(campaign.id),
            'campaign_name': campaign.name,
            'status': campaign.status,
            'total_recipients': campaign.recipient_count,
            'messages': {
                'total': total_messages,
                'queued': queued,
                'sent': sent,
                'delivered': delivered,
                'failed': failed,
            },
            'delivery_rate': round(delivery_rate, 2),
            'created_at': campaign.created_at,
            'updated_at': campaign.updated_at,
            'completed_at': campaign.completed_time,
        })
    
    @swagger_auto_schema(
        operation_description="Get message details for a specific campaign",
        responses={
            200: openapi.Response(
                description="Campaign message details",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'campaign_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'campaign_name': openapi.Schema(type=openapi.TYPE_STRING),
                        'messages': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'id': openapi.Schema(type=openapi.TYPE_STRING),
                                    'recipient': openapi.Schema(type=openapi.TYPE_STRING),
                                    'status': openapi.Schema(type=openapi.TYPE_STRING),
                                    'delivery_status': openapi.Schema(type=openapi.TYPE_STRING),
                                }
                            )
                        ),
                        'count': openapi.Schema(type=openapi.TYPE_INTEGER),
                    }
                )
            )
        }
    )
    @action(detail=True, methods=['get'])
    def messages(self, request, pk=None):
        """
        Get messages for a campaign
        """
        campaign = self.get_object()
        
        # Get all messages for this campaign
        messages = SMSMessage.objects.filter(campaign=campaign)
        
        # Paginate if needed
        page = self.paginate_queryset(messages)
        if page is not None:
            serializer = SMSMessageSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
            
        serializer = SMSMessageSerializer(messages, many=True)
        
        return Response({
            'campaign_id': str(campaign.id),
            'campaign_name': campaign.name,
            'messages': serializer.data,
            'count': messages.count(),
        })
    
    @swagger_auto_schema(
        operation_description="Clone an existing campaign to create a new draft",
        responses={
            201: SMSCampaignSerializer,
            400: "Bad request"
        }
    )
    @action(detail=True, methods=['post'])
    def clone(self, request, pk=None):
        """
        Clone a campaign to create a new draft
        """
        original = self.get_object()
        
        # Create a new campaign with the same data
        new_campaign = SMSCampaign.objects.create(
            user=request.user,
            name=f"Copy of {original.name}",
            message=original.message,
            sender_id=original.sender_id,
            type=original.type,
            status='draft',  # Always create as draft
            template=original.template,
        )
        
        # Clone the groups
        for group in original.groups.all():
            new_campaign.groups.add(group)
            
        # Update recipient count
        new_campaign.recipient_count = new_campaign.get_recipients_count()
        new_campaign.save()
        
        serializer = self.get_serializer(new_campaign)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    @swagger_auto_schema(
        operation_description="Get campaign types",
        responses={
            200: openapi.Response(
                description="Campaign types",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'value': openapi.Schema(type=openapi.TYPE_STRING),
                            'label': openapi.Schema(type=openapi.TYPE_STRING),
                        }
                    )
                )
            )
        }
    )
    @action(detail=False, methods=['get'])
    def types(self, request):
        """
        Get campaign types
        """
        types = [{"value": key, "label": value} for key, value in SMSCampaign.TYPE_CHOICES]
        return Response(types)
    
    @swagger_auto_schema(
        operation_description="Get campaign statuses",
        responses={
            200: openapi.Response(
                description="Campaign statuses",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'value': openapi.Schema(type=openapi.TYPE_STRING),
                            'label': openapi.Schema(type=openapi.TYPE_STRING),
                        }
                    )
                )
            )
        }
    )
    @action(detail=False, methods=['get'])
    def statuses(self, request):
        """
        Get campaign statuses
        """
        statuses = [{"value": key, "label": value} for key, value in SMSCampaign.STATUS_CHOICES]
        return Response(statuses)


class SMSMessageViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows SMS messages to be viewed or edited.
    """
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
        """
        Send a single SMS message without creating a campaign
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        
        # Here you would implement the logic to send the message
        # This is a placeholder
        message = serializer.instance
        message.status = 'sending'
        message.save()
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class PaymentViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows payments to be viewed or edited.
    """
    serializer_class = PaymentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """
        This view returns payments for the currently authenticated user.
        """
        return Payment.objects.filter(user=self.request.user)

    @swagger_auto_schema(
        operation_description="List all payments made by the authenticated user"
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Create a new payment record"
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)


class SMSTemplateViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows SMS templates to be viewed or edited.
    """
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
        operation_description="Create a new webhook endpoint"
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)