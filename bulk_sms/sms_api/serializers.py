# sms_api/serializers.py

from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from phonenumber_field.serializerfields import PhoneNumberField
from django.contrib.auth import authenticate
from django.utils import timezone
from django.core.exceptions import ValidationError
from .models import (
    User, PhoneBook, Contact, SMSCampaign,
    SMSMessage, Payment, SMSTemplate, WebhookEndpoint
)

User = get_user_model()
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _

# Create custom validator for African phone numbers
class AfricanPhoneNumberValidator:
    """
    Validator to ensure phone numbers start with valid African country codes,
    with special handling for Kenya as the default.
    """
    
    def __init__(self):
        self.message = _('Phone number must start with a valid African country code (e.g., +254 for Kenya).')
        
        # List of common African country codes
        self.african_codes = [
            '+20',  # Egypt
            '+212', # Morocco
            '+213', # Algeria
            '+216', # Tunisia
            '+218', # Libya
            '+220', # Gambia
            '+221', # Senegal
            '+222', # Mauritania
            '+223', # Mali
            '+224', # Guinea
            '+225', # Côte d'Ivoire
            '+226', # Burkina Faso
            '+227', # Niger
            '+228', # Togo
            '+229', # Benin
            '+230', # Mauritius
            '+231', # Liberia
            '+232', # Sierra Leone
            '+233', # Ghana
            '+234', # Nigeria
            '+235', # Chad
            '+236', # Central African Republic
            '+237', # Cameroon
            '+238', # Cape Verde
            '+239', # São Tomé and Príncipe
            '+240', # Equatorial Guinea
            '+241', # Gabon
            '+242', # Republic of the Congo
            '+243', # Democratic Republic of the Congo
            '+244', # Angola
            '+245', # Guinea-Bissau
            '+246', # Diego Garcia
            '+247', # Ascension Island
            '+248', # Seychelles
            '+249', # Sudan
            '+250', # Rwanda
            '+251', # Ethiopia
            '+252', # Somalia
            '+253', # Djibouti
            '+254', # Kenya (default)
            '+255', # Tanzania
            '+256', # Uganda
            '+257', # Burundi
            '+258', # Mozambique
            '+260', # Zambia
            '+261', # Madagascar
            '+262', # Réunion
            '+263', # Zimbabwe
            '+264', # Namibia
            '+265', # Malawi
            '+266', # Lesotho
            '+267', # Botswana
            '+268', # Eswatini
            '+269', # Comoros
            '+27',  # South Africa
            '+290', # Saint Helena
            '+291', # Eritrea
            '+297', # Aruba
            '+298', # Faroe Islands
            '+299', # Greenland
        ]
    
    def __call__(self, value):
        # Check if value starts with any of the valid country codes
        if not any(value.startswith(code) for code in self.african_codes):
            raise ValidationError(self.message)
    
    def __eq__(self, other):
        return (
            isinstance(other, AfricanPhoneNumberValidator) and
            self.message == other.message
        )

# Format validator to ensure phone number format is valid
phone_regex = RegexValidator(
    regex=r'^\+[0-9]{1,3}[0-9]{9,12}$',
    message="Phone number must be in format: '+254XXXXXXXXX'. Up to 15 digits allowed."
)


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT serializer that adds user details to the token response.
    """
    username_field = 'company_name'

    def validate(self, attrs):
        # The default result (access/refresh tokens)
        data = super().validate(attrs)
        
        # Add extra responses
        user = self.user
        
        # Check if email is verified
        if not user.email_verified:
            raise serializers.ValidationError(
                {"email": "Email is not verified. Please verify your email before logging in."}
            )
        
        data['user_id'] = str(user.id)
        data['company_name'] = user.company_name
        data['email'] = user.email
        data['phone_number'] = user.phone_number
        data['is_staff'] = user.is_staff
        data['is_email_verified'] = user.email_verified
        
        return data
  

class UserSerializer(serializers.ModelSerializer):
    phone_number = PhoneNumberField(required=False)
    
    class Meta:
        model = User
        fields = ['id', 'phone_number', 'company_name', 'email', 'tokens_balance', 
                  'email_verified', 'metadata', 'date_joined']
        read_only_fields = ['id', 'tokens_balance', 'email_verified', 'date_joined']


class RegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration with validation for mandatory phone number,
    email, company name, password, and optional metadata.
    """
    phone_number = serializers.CharField(
        required=True, 
        max_length=20,
        validators=[phone_regex, AfricanPhoneNumberValidator()]
    )
    company_name = serializers.CharField(required=True, max_length=255)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        style={'input_type': 'password'},
        validators=[validate_password]
    )
    metadata = serializers.JSONField(required=False, default=dict)
    
    class Meta:
        model = User
        fields = ['phone_number', 'password', 'company_name', 'email', 'metadata']
        extra_kwargs = {
            'password': {'write_only': True},
        }
    
    def validate_phone_number(self, value):
        """
        Validate that the phone number is not already registered
        and has proper format with country code.
        """
        # Check if phone number is already registered
        if User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("This phone number is already registered.")
        
        # Ensure Kenya is the default if no country code is specified
        if not value.startswith('+'):
            # Add Kenya's country code if missing
            value = f"+254{value}" if not value.startswith('0') else f"+254{value[1:]}"
        
        return value
    
    def validate_company_name(self, value):
        """
        Validate that the company name is not already registered.
        """
        if User.objects.filter(company_name=value).exists():
            raise serializers.ValidationError("This company name is already registered.")
        return value
    
    def validate_email(self, value):
        """
        Validate that the email is not already registered.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already registered.")
        return value
    
    def validate_metadata(self, value):
        """
        Validate the metadata structure if provided.
        """
        if not isinstance(value, dict):
            raise serializers.ValidationError("Metadata must be a JSON object.")
        return value
    
    def create(self, validated_data):
        """
        Create a new user with the validated data, including proper metadata initialization.
        """
        # Remove password from validated data to handle it separately
        password = validated_data.pop('password')
        
        # Extract metadata or use default
        metadata = validated_data.pop('metadata', {})
        
        # Create base metadata structure
        default_metadata = {
            "preferences": {
                "timezone": "Africa/Nairobi",  # Default to Kenya timezone
                "notifications": {
                    "low_balance": 0,
                    "delivery_reports": False
                }
            }
        }
        
        # Merge provided metadata with defaults (preserving user values where provided)
        merged_metadata = default_metadata.copy()
        for key, value in metadata.items():
            if key in merged_metadata and isinstance(merged_metadata[key], dict) and isinstance(value, dict):
                merged_metadata[key].update(value)
            else:
                merged_metadata[key] = value
        
        # Create user without saving to DB yet
        user = User(**validated_data)
        user.set_password(password)
        user.is_active = True
        user.email_verified = False
        user.metadata = merged_metadata
        
        # Save the user to the database
        user.save()
        
        return user


class EmailVerificationRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class EmailVerificationConfirmSerializer(serializers.Serializer):
    token = serializers.CharField(required=True, min_length=64, max_length=64)
    
    def validate(self, attrs):
        token = attrs.get('token')
        
        try:
            user = User.objects.get(verification_token=token)
        except User.DoesNotExist:
            raise serializers.ValidationError({"token": "Invalid verification token."})
        
        if not is_token_valid(user):
            raise serializers.ValidationError({"token": "Verification token has expired. Please request a new one."})
        
        return attrs


class LoginSerializer(serializers.Serializer):
    company_name = serializers.CharField()
    password = serializers.CharField(style={'input_type': 'password'})
    
    def validate(self, attrs):
        company_name = attrs.get('company_name')
        password = attrs.get('password')
        
        if company_name and password:
            user = authenticate(
                request=self.context.get('request'),
                company_name=company_name,
                password=password
            )
            
            if not user:
                raise serializers.ValidationError('Invalid credentials', code='authorization')
            
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled', code='authorization')
            
            # Verify email before allowing login (optional - you can comment this out if you want to allow 
            # login before email verification)
            if not user.email_verified:
                raise serializers.ValidationError('Email is not verified. Please verify your email before logging in.', 
                                                code='authorization')
            
            attrs['user'] = user
            return attrs
        
        raise serializers.ValidationError('Must include "company_name" and "password"', code='authorization')

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    confirm_password = serializers.CharField(required=True)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"new_password": "Password fields didn't match."})
        return attrs


class ResetPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class ResetPasswordConfirmSerializer(serializers.Serializer):
    token = serializers.CharField(required=True, min_length=64, max_length=64)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    confirm_password = serializers.CharField(required=True)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"new_password": "Password fields didn't match."})
        
        return attrs


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    phone_number = serializers.CharField(
        required=True, 
        max_length=20,
        validators=[phone_regex, AfricanPhoneNumberValidator()]
    )
    
    class Meta:
        model = User
        fields = ['email', 'phone_number', 'company_name']
    
    def validate_email(self, value):
        user = self.context['request'].user
        if User.objects.exclude(pk=user.pk).filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        
        # If email is changed, it needs to be verified again
        current_email = user.email
        if value != current_email:
            self.context['email_changed'] = True
        
        return value
    
    def validate_phone_number(self, value):
        user = self.context['request'].user
        
        # Ensure Kenya is the default if no country code is specified
        if not value.startswith('+'):
            # Add Kenya's country code if missing
            value = f"+254{value}" if not value.startswith('0') else f"+254{value[1:]}"
        
        # Check if phone number is unique
        if User.objects.exclude(pk=user.pk).filter(phone_number=value).exists():
            raise serializers.ValidationError("This phone number is already in use.")
        
        return value
    
    def update(self, instance, validated_data):
        email_changed = False
        if 'email' in validated_data and validated_data['email'] != instance.email:
            email_changed = True
        
        # Update instance with validated data
        instance = super().update(instance, validated_data)
        
        if email_changed:
            # Mark email as unverified and generate new verification token
            instance.email_verified = False
            token = generate_verification_token()
            instance.verification_token = token
            instance.token_created_at = timezone.now()
            instance.token_expiration = timezone.now() + timedelta(hours=24)
            instance.save()
            
            # Send verification email
            send_verification_email(instance, token)
        
        return instance


class PhoneBookSerializer(serializers.ModelSerializer):
    class Meta:
        model = PhoneBook
        fields = ('id', 'name', 'metadata', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ('id', 'phonebook', 'phone_number', 'metadata', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')

    def validate_phonebook(self, value):
        if value.user != self.context['request'].user:
            raise serializers.ValidationError("You don't have permission to add contacts to this phonebook.")
        return value


class SMSCampaignSerializer(serializers.ModelSerializer):
    class Meta:
        model = SMSCampaign
        fields = ('id', 'name', 'message', 'sender_id', 'status', 'metadata', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class SMSMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = SMSMessage
        fields = ('id', 'campaign', 'recipient', 'content', 'status', 'metadata', 'created_at', 'updated_at')
        read_only_fields = ('id', 'status', 'created_at', 'updated_at')

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ('id', 'amount', 'status', 'payment_date', 'metadata', 'created_at', 'updated_at')
        read_only_fields = ('id', 'status', 'payment_date', 'created_at', 'updated_at')

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class SMSTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = SMSTemplate
        fields = ('id', 'name', 'content', 'metadata', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class WebhookEndpointSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebhookEndpoint
        fields = ('id', 'url', 'is_active', 'metadata', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)