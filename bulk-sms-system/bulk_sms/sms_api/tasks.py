from celery import shared_task
from django.conf import settings
from django.utils import timezone
from utils.sms_gateways import SMSGatewayFactory
from utils.webhooks import send_event_to_user_webhooks
import logging
import time
import random
from .models import SMSMessage, Campaign, Contact, User

logger = logging.getLogger(__name__)


@shared_task(name="send_single_sms")
def send_single_sms(message_id):
    """Send a single SMS message"""
    try:
        # Get the message
        message = SMSMessage.objects.get(id=message_id)
        
        # Don't resend already sent messages
        if message.status not in ['queued', 'sending']:
            logger.warning(f"Attempted to send message {message_id} with status {message.status}")
            return False
            
        # Update status to sending
        message.status = 'sending'
        message.save(update_fields=['status', 'updated_at'])
        
        # Get the SMS gateway
        gateway = SMSGatewayFactory.get_gateway(settings.SMS_GATEWAY_PROVIDER)
        
        # Send the SMS
        sender_id = message.campaign.sender_id if message.campaign else settings.DEFAULT_SENDER_ID
        response = gateway.send_sms(message.recipient, message.content, sender_id)
        
        if response.get('status') == 'success':
            # Update message with success info
            message.status = 'sent'
            message.message_id = response.get('message_id')
            message.metadata.update({
                'provider_response': response,
                'sent_at': timezone.now().isoformat()
            })
            message.save(update_fields=['status', 'message_id', 'metadata', 'updated_at'])
            
            # Deduct tokens from user balance
            user = message.user
            segments = message.segments
            user.tokens_balance = max(0, user.tokens_balance - segments)
            user.save(update_fields=['tokens_balance'])
            
            # Update contact's last_message_sent
            if message.contact:
                message.contact.last_message_sent = timezone.now()
                message.contact.save(update_fields=['last_message_sent', 'updated_at'])
            
            # Queue task to check delivery status
            update_message_status.apply_async(
                args=[str(message.id)],
                countdown=30  # Check after 30 seconds
            )
            
            # Send webhook event
            send_event_to_user_webhooks(
                user_id=str(message.user.id),
                event_type='message.sent',
                data={
                    'message_id': str(message.id),
                    'recipient': message.recipient,
                    'status': message.status,
                    'campaign_id': str(message.campaign.id) if message.campaign else None,
                    'segments': message.segments,
                    'sent_at': timezone.now().isoformat()
                }
            )
            
            return True
        else:
            # Update message with error info
            message.status = 'failed'
            message.error_message = response.get('error', 'Unknown error')
            message.metadata.update({
                'provider_response': response,
                'failed_at': timezone.now().isoformat()
            })
            message.save(update_fields=['status', 'error_message', 'metadata', 'updated_at'])
            
            # Send webhook event
            send_event_to_user_webhooks(
                user_id=str(message.user.id),
                event_type='message.failed',
                data={
                    'message_id': str(message.id),
                    'recipient': message.recipient,
                    'status': message.status,
                    'error': message.error_message,
                    'campaign_id': str(message.campaign.id) if message.campaign else None,
                    'failed_at': timezone.now().isoformat()
                }
            )
            
            return False
            
    except Exception as e:
        logger.error(f"Error sending SMS {message_id}: {str(e)}")
        
        # Try to update message status if possible
        try:
            message = SMSMessage.objects.get(id=message_id)
            message.status = 'failed'
            message.error_message = str(e)
            message.metadata.update({
                'exception': str(e),
                'failed_at': timezone.now().isoformat()
            })
            message.save(update_fields=['status', 'error_message', 'metadata', 'updated_at'])
            
            # Send webhook event
            send_event_to_user_webhooks(
                user_id=str(message.user.id),
                event_type='message.failed',
                data={
                    'message_id': str(message.id),
                    'recipient': message.recipient,
                    'status': message.status,
                    'error': str(e),
                    'campaign_id': str(message.campaign.id) if message.campaign else None,
                    'failed_at': timezone.now().isoformat()
                }
            )
        except:
            pass
            
        return False


@shared_task(name="send_campaign_messages")
def send_campaign_messages(campaign_id):
    """Process sending all messages for a campaign"""
    try:
        # Get the campaign
        campaign = Campaign.objects.get(id=campaign_id)
        
        # Only process campaigns that are in draft or scheduled state
        if campaign.status not in ['draft', 'scheduled']:
            logger.warning(f"Attempted to process campaign {campaign_id} with status {campaign.status}")
            return False
        
        # Update campaign status to processing
        campaign.status = 'processing'
        campaign.save(update_fields=['status', 'updated_at'])
        
        # Get all contacts from the campaign groups
        contacts = []
        for group in campaign.groups.all():
            contacts.extend(list(group.contacts.all()))
        
        # Remove duplicates by phone number
        unique_contacts = {}
        for contact in contacts:
            unique_contacts[contact.phone_number] = contact
        
        # Count total recipients
        recipient_count = len(unique_contacts)
        campaign.recipient_count = recipient_count
        campaign.save(update_fields=['recipient_count', 'updated_at'])
        
        # Check if user has enough tokens
        user = campaign.user
        required_tokens = recipient_count  # Simple calculation, 1 token per recipient
        if user.tokens_balance < required_tokens:
            campaign.status = 'failed'
            campaign.metadata.update({
                'error': 'Insufficient tokens',
                'required_tokens': required_tokens,
                'available_tokens': user.tokens_balance,
                'failed_at': timezone.now().isoformat()
            })
            campaign.save(update_fields=['status', 'metadata', 'updated_at'])
            
            # Send webhook event for campaign failure
            send_event_to_user_webhooks(
                user_id=str(user.id),
                event_type='campaign.failed',
                data={
                    'campaign_id': str(campaign.id),
                    'name': campaign.name,
                    'status': campaign.status,
                    'error': 'Insufficient tokens',
                    'required_tokens': required_tokens,
                    'available_tokens': user.tokens_balance,
                    'failed_at': timezone.now().isoformat()
                }
            )
            
            return False
        
        # Create and queue all messages
        for phone, contact in unique_contacts.items():
            # Create message record
            message = SMSMessage.objects.create(
                campaign=campaign,
                user=user,
                contact=contact,
                recipient=phone,
                content=campaign.message,
                status='queued',
                segments=max(1, len(campaign.message) // 160 + (1 if len(campaign.message) % 160 > 0 else 0))
            )
            
            # Queue the message for sending with some delay to avoid rate limits
            send_single_sms.apply_async(
                args=[str(message.id)],
                countdown=random.randint(1, 5)  # Random delay between 1-5 seconds
            )
        
        # Update campaign status to sending
        campaign.status = 'sending'
        campaign.save(update_fields=['status', 'updated_at'])
        
        # Schedule a task to check campaign completion
        check_campaign_completion.apply_async(
            args=[str(campaign.id)],
            countdown=60  # Check after 1 minute
        )
        
        # Send webhook event for campaign started
        send_event_to_user_webhooks(
            user_id=str(user.id),
            event_type='campaign.started',
            data={
                'campaign_id': str(campaign.id),
                'name': campaign.name,
                'status': campaign.status,
                'recipient_count': recipient_count,
                'started_at': timezone.now().isoformat()
            }
        )
        
        return True
        
    except Exception as e:
        logger.error(f"Error processing campaign {campaign_id}: {str(e)}")
        
        # Try to update campaign status if possible
        try:
            campaign = Campaign.objects.get(id=campaign_id)
            campaign.status = 'failed'
            campaign.metadata.update({
                'error': str(e),
                'failed_at': timezone.now().isoformat()
            })
            campaign.save(update_fields=['status', 'metadata', 'updated_at'])
            
            # Send webhook event for campaign failure
            send_event_to_user_webhooks(
                user_id=str(campaign.user.id),
                event_type='campaign.failed',
                data={
                    'campaign_id': str(campaign.id),
                    'name': campaign.name,
                    'status': campaign.status,
                    'error': str(e),
                    'failed_at': timezone.now().isoformat()
                }
            )
        except:
            pass
            
        return False


@shared_task(name="check_campaign_completion")
def check_campaign_completion(campaign_id):
    """Check if a campaign is completed (all messages sent or failed)"""
    try:
        # Get the campaign
        campaign = Campaign.objects.get(id=campaign_id)
        
        # Skip if campaign is already completed or failed
        if campaign.status in ['completed', 'failed', 'cancelled']:
            return True
        
        # Count messages by status
        total_messages = SMSMessage.objects.filter(campaign_id=campaign_id).count()
        pending_messages = SMSMessage.objects.filter(campaign_id=campaign_id, status__in=['queued', 'sending']).count()
        delivered_messages = SMSMessage.objects.filter(campaign_id=campaign_id, delivery_status='delivered').count()
        
        # Calculate delivery rate
        campaign.delivery_rate = (delivered_messages / total_messages * 100) if total_messages > 0 else 0
        campaign.save(update_fields=['delivery_rate', 'updated_at'])
        
        # If no pending messages, mark as completed
        if pending_messages == 0:
            campaign.status = 'completed'
            campaign.completed_time = timezone.now()
            campaign.save(update_fields=['status', 'completed_time', 'updated_at'])
            
            # Send webhook event for campaign completion
            send_event_to_user_webhooks(
                user_id=str(campaign.user.id),
                event_type='campaign.completed',
                data={
                    'campaign_id': str(campaign.id),
                    'name': campaign.name,
                    'status': campaign.status,
                    'recipient_count': campaign.recipient_count,
                    'delivery_rate': campaign.delivery_rate,
                    'completed_at': timezone.now().isoformat()
                }
            )
            
            return True
        
        # Otherwise, schedule another check
        check_campaign_completion.apply_async(
            args=[str(campaign.id)],
            countdown=60  # Check again in 1 minute
        )
        
        return False
        
    except Exception as e:
        logger.error(f"Error checking campaign completion {campaign_id}: {str(e)}")
        return False


@shared_task(name="update_message_status")
def update_message_status(message_id):
    """Update the delivery status of a message"""
    try:
        # Get the message
        message = SMSMessage.objects.get(id=message_id)
        
        # Skip if no provider message ID or already delivered
        if not message.message_id or message.delivery_status in ['delivered', 'failed', 'expired', 'rejected']:
            return False
        
        # Get the SMS gateway
        gateway = SMSGatewayFactory.get_gateway(settings.SMS_GATEWAY_PROVIDER)
        
        # Check the delivery status
        response = gateway.check_delivery_status(message.message_id)
        
        if response.get('status') == 'success':
            # Store previous status
            previous_status = message.delivery_status
            
            # Update message with delivery status
            message.delivery_status = response.get('delivery_status', 'unknown')
            
            # If delivered, set delivery time
            if message.delivery_status == 'delivered' and not message.delivery_time:
                message.delivery_time = timezone.now()
            
            message.metadata.update({
                'status_response': response,
                'status_checked_at': timezone.now().isoformat()
            })
            message.save(update_fields=['delivery_status', 'delivery_time', 'metadata', 'updated_at'])
            
            # If status has changed to delivered or failed, send webhook
            if previous_status != message.delivery_status and message.delivery_status in ['delivered', 'failed']:
                event_type = f"message.{message.delivery_status}"
                
                send_event_to_user_webhooks(
                    user_id=str(message.user.id),
                    event_type=event_type,
                    data={
                        'message_id': str(message.id),
                        'recipient': message.recipient,
                        'status': message.status,
                        'delivery_status': message.delivery_status,
                        'campaign_id': str(message.campaign.id) if message.campaign else None,
                        'delivered_at': message.delivery_time.isoformat() if message.delivery_time else None
                    }
                )
            
            # Schedule another check if not in final state
            if message.delivery_status not in ['delivered', 'failed', 'expired', 'rejected']:
                update_message_status.apply_async(
                    args=[str(message.id)],
                    countdown=60  # Check again in 1 minute
                )
            
            return True
        else:
            # Update message with error info
            message.metadata.update({
                'status_response': response,
                'status_check_error': response.get('error', 'Unknown error'),
                'status_checked_at': timezone.now().isoformat()
            })
            message.save(update_fields=['metadata', 'updated_at'])
            
            # Schedule another check
            update_message_status.apply_async(
                args=[str(message.id)],
                countdown=60  # Check again in 1 minute
            )
            
            return False
            
    except Exception as e:
        logger.error(f"Error updating message status {message_id}: {str(e)}")
        return False


@shared_task(name="update_campaign_statuses")
def update_campaign_statuses():
    """Update the status of all active campaigns"""
    # Get all campaigns that are not completed, failed, or cancelled
    active_campaigns = Campaign.objects.filter(
        status__in=['scheduled', 'sending', 'processing']
    )
    
    for campaign in active_campaigns:
        # If scheduled and it's time to send, process the campaign
        if campaign.status == 'scheduled' and campaign.scheduled_time and campaign.scheduled_time <= timezone.now():
            send_campaign_messages.delay(str(campaign.id))
            
        # If sending or processing, check completion
        elif campaign.status in ['sending', 'processing']:
            check_campaign_completion.delay(str(campaign.id))
    
    return True


@shared_task(name="process_scheduled_campaigns")
def process_scheduled_campaigns():
    """Process all campaigns that are scheduled to run now"""
    # Get all scheduled campaigns whose time has come
    now = timezone.now()
    scheduled_campaigns = Campaign.objects.filter(
        status='scheduled',
        scheduled_time__lte=now
    )
    
    for campaign in scheduled_campaigns:
        send_campaign_messages.delay(str(campaign.id))
    
    return True 