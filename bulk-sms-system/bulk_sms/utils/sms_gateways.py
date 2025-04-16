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
from twilio.rest import Client

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
        # Use settings rather than direct env vars for consistency
        self.api_key = settings.AFRICASTALKING_API_KEY
        self.username = settings.AFRICASTALKING_USERNAME
        self.sender_id = settings.AFRICASTALKING_SENDER_ID
        try:
            # Initialize the Africa's Talking SDK
            self.at_gateway = africastalking.initialize(self.username, self.api_key)
            self.sms = self.at_gateway.SMS
        except Exception as e:
            logger.error(f"Error initializing Africa's Talking: {str(e)}")
            self.sms = None
        
    def send_sms(self, to, message, sender=None):
        """Send an SMS message via Africa's Talking"""
        try:
            # Use the SDK to send SMS
            if not sender:
                sender = self.sender_id
                
            # Ensure the number is properly formatted
            if not to.startswith('+'):
                to = '+' + to
                
            # Send the SMS
            response = self.sms.send(
                message=message,
                recipients=[to],
                sender_id=sender
            )
            
            # Process the response
            if response and 'SMSMessageData' in response and 'Recipients' in response['SMSMessageData']:
                recipients = response['SMSMessageData']['Recipients']
                if recipients and len(recipients) > 0:
                    recipient = recipients[0]
                    status_code = recipient.get('statusCode')
                    
                    if status_code == 101 or status_code == 100:
                        # Success codes
                        return {
                            'status': 'success',
                            'message_id': recipient.get('messageId'),
                            'to': recipient.get('number'),
                            'provider': 'africastalking',
                            'status_code': status_code,
                            'cost': recipient.get('cost')
                        }
                    else:
                        # Error codes
                        return {
                            'status': 'error',
                            'error': recipient.get('status'),
                            'to': recipient.get('number'),
                            'provider': 'africastalking',
                            'status_code': status_code
                        }
            
            # Handle unexpected response format
            return {
                'status': 'error',
                'error': 'Invalid response from Africa\'s Talking',
                'to': to,
                'message': message,
                'provider': 'africastalking',
                'raw_response': response
            }
            
        except Exception as e:
            logger.error(f"Error sending SMS via Africa's Talking: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'to': to,
                'message': message,
                'provider': 'africastalking'
            }
    
    def check_delivery_status(self, message_id):
        """Check the delivery status of a message via Africa's Talking"""
        try:
            # Africa's Talking provides delivery reports via callbacks
            # For direct status checking, we need to simulate based on the last status
            # We'll implement a basic mapping to our internal statuses
            
            # In a real implementation, you might want to store message statuses in a database
            # and update them when callbacks are received
            
            # For now, we'll just return 'sent' status as Africa's Talking doesn't have
            # a direct API for checking message status by ID
            return {
                'status': 'success',
                'message_id': message_id,
                'delivery_status': 'sent',  # Default to 'sent' since we can't check directly
                'provider': 'africastalking'
            }
            
        except Exception as e:
            logger.error(f"Error checking delivery status via Africa's Talking: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'message_id': message_id,
                'provider': 'africastalking'
            }


class TwilioGateway(SMSGatewayInterface):
    """Integration with Twilio SMS Gateway"""
    def __init__(self):
        self.account_sid = settings.TWILIO_ACCOUNT_SID
        self.auth_token = settings.TWILIO_AUTH_TOKEN
        self.phone_number = settings.TWILIO_PHONE_NUMBER
        self.client = Client(self.account_sid, self.auth_token)
        
    def send_sms(self, to, message, sender=None):
        """Send an SMS message via Twilio"""
        try:
            if not sender:
                sender = self.phone_number
                
            # Format the phone number if needed
            to = format_phone_number(to)
            
            # Send the message
            twilio_message = self.client.messages.create(
                body=message,
                from_=sender,
                to=to
            )
            
            return {
                'status': 'success',
                'message_id': twilio_message.sid,
                'to': to,
                'message': message,
                'provider': 'twilio'
            }
        except Exception as e:
            logger.error(f"Error sending SMS via Twilio: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'to': to,
                'message': message,
                'provider': 'twilio'
            }
    
    def check_delivery_status(self, message_id):
        """Check the delivery status of a message via Twilio"""
        try:
            message = self.client.messages(message_id).fetch()
            
            # Map Twilio status to our internal status
            status_map = {
                'queued': 'queued',
                'sending': 'sending',
                'sent': 'sent',
                'delivered': 'delivered',
                'undelivered': 'failed',
                'failed': 'failed'
            }
            
            return {
                'status': 'success',
                'message_id': message_id,
                'delivery_status': status_map.get(message.status, 'unknown'),
                'provider': 'twilio'
            }
        except Exception as e:
            logger.error(f"Error checking delivery status via Twilio: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'message_id': message_id,
                'provider': 'twilio'
            }


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