import json
import logging
import requests
import uuid
from django.utils import timezone
from celery import shared_task

logger = logging.getLogger(__name__)

@shared_task(name="send_webhook_event", max_retries=3)
def send_webhook_event(webhook_url, event_type, data, user_id=None):
    """
    Send a webhook event to the specified URL.
    
    Args:
        webhook_url (str): The URL to send the webhook to
        event_type (str): The type of event (e.g., 'message.sent')
        data (dict): The event data to send
        user_id (str, optional): The ID of the user who owns the webhook
        
    Returns:
        dict: Information about the webhook delivery
    """
    try:
        # Create event ID
        event_id = str(uuid.uuid4())
        
        # Format the payload
        payload = {
            'id': event_id,
            'event': event_type,
            'created': timezone.now().isoformat(),
            'data': data
        }
        
        # Add user ID if provided
        if user_id:
            payload['user_id'] = user_id
        
        # Set headers
        headers = {
            'Content-Type': 'application/json',
            'X-GDA-Event': event_type,
            'X-GDA-Signature': event_id  # Simple signature for now
        }
        
        # Send the webhook
        response = requests.post(
            webhook_url,
            json=payload,
            headers=headers,
            timeout=5  # Timeout after 5 seconds
        )
        
        # Log the response
        if response.status_code >= 200 and response.status_code < 300:
            logger.info(f"Webhook {event_id} delivered successfully to {webhook_url}")
            success = True
        else:
            logger.warning(f"Webhook {event_id} to {webhook_url} received non-success response: {response.status_code}")
            success = False
        
        # Return delivery info
        return {
            'event_id': event_id,
            'event_type': event_type,
            'url': webhook_url,
            'status_code': response.status_code,
            'success': success,
            'timestamp': timezone.now().isoformat(),
            'response': response.text[:500]  # Limit response size
        }
        
    except Exception as e:
        logger.error(f"Error delivering webhook to {webhook_url}: {str(e)}")
        
        # Return error info
        return {
            'event_id': str(uuid.uuid4()),
            'event_type': event_type,
            'url': webhook_url,
            'success': False,
            'error': str(e),
            'timestamp': timezone.now().isoformat()
        }

def send_event_to_user_webhooks(user_id, event_type, data):
    """
    Send an event to all active webhooks for a specific user.
    
    Args:
        user_id (str): The ID of the user whose webhooks to send to
        event_type (str): The type of event (e.g., 'message.sent')
        data (dict): The event data to send
        
    Returns:
        int: The number of webhooks the event was sent to
    """
    from sms_api.models import WebhookEndpoint
    
    # Find all active webhooks for this user
    webhooks = WebhookEndpoint.objects.filter(
        user_id=user_id,
        is_active=True
    )
    
    # Send the event to each webhook
    for webhook in webhooks:
        send_webhook_event.delay(webhook.url, event_type, data, user_id)
    
    return len(webhooks) 