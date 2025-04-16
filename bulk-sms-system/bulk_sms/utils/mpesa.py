import base64
import json
import logging
import requests
from datetime import datetime
from django.conf import settings
import time

logger = logging.getLogger(__name__)

class MPesaClient:
    """Client for interacting with the M-Pesa Daraja API"""
    
    def __init__(self):
        self.consumer_key = settings.MPESA_CONSUMER_KEY
        self.consumer_secret = settings.MPESA_CONSUMER_SECRET
        self.business_shortcode = settings.MPESA_SHORTCODE
        self.passkey = settings.MPESA_PASSKEY
        self.callback_url = settings.MPESA_CALLBACK_URL
        self.access_token_url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
        self.stkpush_url = 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
        self.query_url = 'https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query'
        
        # Switch to production URLs if in production mode
        if not settings.DEBUG:
            self.access_token_url = 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
            self.stkpush_url = 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
            self.query_url = 'https://api.safaricom.co.ke/mpesa/stkpushquery/v1/query'
    
    def get_access_token(self):
        """Get OAuth access token from Safaricom"""
        try:
            auth_string = f"{self.consumer_key}:{self.consumer_secret}"
            auth_bytes = auth_string.encode("ascii")
            encoded_auth = base64.b64encode(auth_bytes).decode("ascii")
            
            headers = {
                "Authorization": f"Basic {encoded_auth}"
            }
            
            response = requests.get(self.access_token_url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('access_token')
            else:
                logger.error(f"Failed to get access token: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting M-Pesa access token: {str(e)}")
            return None
    
    def generate_password(self):
        """Generate the password for STK Push"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        password_str = f"{self.business_shortcode}{self.passkey}{timestamp}"
        password_bytes = password_str.encode('ascii')
        return base64.b64encode(password_bytes).decode('utf-8'), timestamp
    
    def initiate_stk_push(self, phone_number, amount, account_reference, transaction_desc):
        """Initiate an STK Push request to the customer's phone"""
        try:
            access_token = self.get_access_token()
            if not access_token:
                return {
                    'status': 'error',
                    'message': 'Failed to get access token'
                }
            
            # Generate the password and timestamp    
            password, timestamp = self.generate_password()
            
            # Format phone number (remove leading 0 or +)
            if phone_number.startswith('+'):
                phone_number = phone_number[1:]
            if phone_number.startswith('0'):
                phone_number = '254' + phone_number[1:]
            
            # Prepare the request body
            payload = {
                "BusinessShortCode": self.business_shortcode,
                "Password": password,
                "Timestamp": timestamp,
                "TransactionType": "CustomerPayBillOnline",
                "Amount": int(amount),
                "PartyA": phone_number,
                "PartyB": self.business_shortcode,
                "PhoneNumber": phone_number,
                "CallBackURL": self.callback_url,
                "AccountReference": account_reference,
                "TransactionDesc": transaction_desc
            }
            
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            # Make the request
            response = requests.post(self.stkpush_url, json=payload, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ResponseCode') == '0':
                    return {
                        'status': 'success',
                        'message': 'STK push initiated',
                        'checkout_request_id': data.get('CheckoutRequestID'),
                        'response': data
                    }
                else:
                    return {
                        'status': 'error',
                        'message': f"STK push failed: {data.get('ResponseDescription')}",
                        'response': data
                    }
            else:
                return {
                    'status': 'error',
                    'message': f"STK push request failed with status {response.status_code}",
                    'response': response.text
                }
                
        except Exception as e:
            logger.error(f"Error initiating STK push: {str(e)}")
            return {
                'status': 'error',
                'message': f"Error: {str(e)}"
            }
    
    def query_stk_status(self, checkout_request_id):
        """Query the status of an STK Push transaction"""
        try:
            access_token = self.get_access_token()
            if not access_token:
                return {
                    'status': 'error',
                    'message': 'Failed to get access token'
                }
            
            # Generate the password and timestamp    
            password, timestamp = self.generate_password()
            
            # Prepare the request body
            payload = {
                "BusinessShortCode": self.business_shortcode,
                "Password": password,
                "Timestamp": timestamp,
                "CheckoutRequestID": checkout_request_id
            }
            
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            # Make the request
            response = requests.post(self.query_url, json=payload, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'status': 'success',
                    'response': data
                }
            else:
                return {
                    'status': 'error',
                    'message': f"Query failed with status {response.status_code}",
                    'response': response.text
                }
                
        except Exception as e:
            logger.error(f"Error querying STK status: {str(e)}")
            return {
                'status': 'error',
                'message': f"Error: {str(e)}"
            } 