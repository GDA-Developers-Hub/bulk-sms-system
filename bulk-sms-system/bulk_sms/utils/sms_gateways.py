# utils/sms_gateways.py
import requests
import json
import os
from dotenv import load_dotenv
import africastalking
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import random
import secrets
import string
from django.core.mail import send_mail
import logging

load_dotenv()

logger = logging.getLogger(__name__)

def generate_verification_token():
    """Generate a secure random token for email verification"""
    # Create a random string with letters and digits
    alphabet = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(alphabet) for _ in range(64))
    return token

def is_token_valid(user):
    """Check if a user's verification token is still valid"""
    if not user.token_created_at or not user.token_expiration:
        return False
    
    return timezone.now() <= user.token_expiration

def send_verification_email(user, token):
    """Send verification email to the user"""
    verification_url = f"{settings.FRONTEND_URL}/verify-email/{token}"
    
    subject = "Verify Your Email Address"
    message = f"""
    Hello {user.company_name},
    
    Please verify your email address by clicking on the link below:
    
    {verification_url}
    
    This link will expire in 24 hours.
    
    If you did not create an account, please ignore this email.
    
    Thank you,
    GDA Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        return True, "Verification email sent successfully"
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {str(e)}")
        return False, str(e)

def send_password_reset_email(user, token):
    """Send password reset email to the user"""
    reset_url = f"{settings.FRONTEND_URL}/reset-password/{token}"
    
    subject = "Reset Your Password"
    message = f"""
    Hello {user.company_name},
    
    You requested to reset your password. Please click on the link below to set a new password:
    
    {reset_url}
    
    This link will expire in 24 hours.
    
    If you did not request a password reset, please ignore this email or contact support if you have concerns.
    
    Thank you,
    GDA Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        return True, "Password reset email sent successfully"
    except Exception as e:
        logger.error(f"Failed to send password reset email to {user.email}: {str(e)}")
        return False, str(e)

def format_phone_number(phone_number):
    """
    Format a phone number to ensure it has the proper country code.
    Default to Kenya (+254) if no country code is provided.
    """
    # Remove any spaces or special characters
    cleaned_number = ''.join(filter(lambda x: x.isdigit() or x == '+', phone_number))
    
    # If it doesn't start with +, assume it's a Kenyan number
    if not cleaned_number.startswith('+'):
        # If it starts with 0, remove the 0 and add +254
        if cleaned_number.startswith('0'):
            cleaned_number = '+254' + cleaned_number[1:]
        else:
            # Otherwise just add +254
            cleaned_number = '+' + cleaned_number
    
    return cleaned_number

def validate_african_phone(phone_number):
    """
    Validate that a phone number belongs to an African country.
    Returns (is_valid, formatted_number, error_message)
    """
    # List of African country codes (same as in the validator)
    african_codes = [
        '+20', '+212', '+213', '+216', '+218', '+220', '+221', '+222',
        '+223', '+224', '+225', '+226', '+227', '+228', '+229', '+230',
        '+231', '+232', '+233', '+234', '+235', '+236', '+237', '+238',
        '+239', '+240', '+241', '+242', '+243', '+244', '+245', '+246',
        '+247', '+248', '+249', '+250', '+251', '+252', '+253', '+254',
        '+255', '+256', '+257', '+258', '+260', '+261', '+262', '+263',
        '+264', '+265', '+266', '+267', '+268', '+269', '+27', '+290',
        '+291', '+297', '+298', '+299'
    ]
    
    # Format the number first
    formatted = format_phone_number(phone_number)
    
    # Check if it starts with a valid African code
    if not any(formatted.startswith(code) for code in african_codes):
        return False, formatted, "Phone number must start with a valid African country code."
    
    # Check phone number length (should be between 10 and 15 digits total)
    if not (10 <= len(formatted.replace('+', '')) <= 15):
        return False, formatted, "Phone number must be between 10 and 15 digits."
    
    return True, formatted, None


class SMSGatewayInterface:
    """Base interface for SMS gateways"""
    def send_sms(self, to, message, sender=None):
        """Send an SMS message"""
        raise NotImplementedError("Subclasses must implement this method")
    
    def check_delivery_status(self, message_id):
        """Check the delivery status of a message"""
        raise NotImplementedError("Subclasses must implement this method")


class AfricasTalkingGateway(SMSGatewayInterface):
    """Integration with Africa's Talking SMS Gateway"""
    def __init__(self):
        self.api_key = os.getenv('AT_API_KEY')
        self.username = os.getenv('AT_USERNAME')
        self.api_url = "https://api.africastalking.com/version1/messaging"
        
    def send_sms(self, to, message, sender=None):
        """Send an SMS message via Africa's Talking"""
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
            'ApiKey': self.api_key
        }
        
        data = {
            'username': self.username,
            'message': message,
            'to': to
        }
        
        if sender:
            data['from'] = sender
            
        response = requests.post(self.api_url, headers=headers, data=data)
        
        return response.json()
    
    def check_delivery_status(self, message_id):
        """Check the delivery status of a message via Africa's Talking"""
        # Implementation varies based on Africa's Talking API for delivery reports
        pass


# class TwilioGateway(SMSGatewayInterface):
#     """Integration with Twilio SMS Gateway"""
#     def __init__(self):
#         self.account_sid = os.getenv('TWILIO_ACCOUNT_SID')
#         self.auth_token = os.getenv('TWILIO_AUTH_TOKEN')
#         self.api_url = f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}/Messages.json"
        
#     def send_sms(self, to, message, sender=None):
#         """Send an SMS message via Twilio"""
#         if not sender:
#             sender = os.getenv('TWILIO_PHONE_NUMBER')
            
#         auth = (self.account_sid, self.auth_token)
#         data = {
#             'To': to,
#             'From': sender,
#             'Body': message
#         }
        
#         response = requests.post(self.api_url, auth=auth, data=data)
        
#         return response.json()
    
#     def check_delivery_status(self, message_id):
#         """Check the delivery status of a message via Twilio"""
#         url = f"{self.api_url.replace('.json', '')}/{message_id}.json"
#         auth = (self.account_sid, self.auth_token)
        
#         response = requests.get(url, auth=auth)
        
#         return response.json()


class SMSGatewayFactory:
    """Factory to create SMS gateway instances"""
    @staticmethod
    def get_gateway(provider_name):
        """Get an instance of the specified SMS gateway"""
        if provider_name.lower() == 'africastalking':
            return AfricasTalkingGateway()
        elif provider_name.lower() == 'twilio':
            return TwilioGateway()
        else:
            raise ValueError(f"Unsupported SMS gateway provider: {provider_name}")