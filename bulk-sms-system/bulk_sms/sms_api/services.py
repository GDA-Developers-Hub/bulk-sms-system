import re
import logging
from typing import Dict, List, Tuple
from django.conf import settings
from django.utils import timezone
from .models import MessageTemplate, SMSMessage, Campaign
import africastalking

# Try to import profanity_check, use fallback if not available
try:
    from profanity_check import predict_prob
    HAS_PROFANITY_CHECK = True
except ImportError:
    HAS_PROFANITY_CHECK = False
    logging.warning("profanity_check package not found. Using basic profanity detection.")

# Basic list of common profane words - this is a very basic fallback
BASIC_PROFANE_WORDS = {
    'profanity',  # placeholder - add actual words as needed
}

logger = logging.getLogger(__name__)

class SMSService:
    """Service for handling SMS operations"""

    def __init__(self):
        """Initialize the SMS service with Africa's Talking credentials"""
        self.username = settings.AFRICAS_TALKING_USERNAME
        self.api_key = settings.AFRICAS_TALKING_API_KEY
        self.sender_id = settings.AFRICAS_TALKING_SENDER_ID
        
        # Initialize Africa's Talking SDK
        africastalking.initialize(self.username, self.api_key)
        self.sms = africastalking.SMS

    def send_single_sms(self, message: SMSMessage) -> bool:
        """
        Send a single SMS message
        Returns: True if successful, False otherwise
        """
        try:
            # Update message status to sending
            message.status = SMSMessage.Status.SENDING
            message.save(update_fields=['status', 'updated_at'])

            # Send the message
            result = self.sms.send(
                message=message.content,
                recipients=[message.recipient],
                sender_id=self.sender_id if self.sender_id else None
            )

            # Process the result
            if result and 'SMSMessageData' in result:
                msg_data = result['SMSMessageData']
                recipients = msg_data.get('Recipients', [])
                
                if recipients and len(recipients) > 0:
                    msg_result = recipients[0]
                    message.message_id = msg_result.get('messageId')
                    message.status = SMSMessage.Status.SENT
                    message.delivery_status = 'sent'
                    message.metadata.update({
                        'gateway_response': msg_result,
                        'sent_at': timezone.now().isoformat()
                    })
                    
                    # Deduct tokens from user's balance
                    user = message.user
                    user.tokens_balance -= message.segments
                    user.save(update_fields=['tokens_balance'])

                    message.save(update_fields=[
                        'message_id', 'status', 'delivery_status',
                        'metadata', 'updated_at'
                    ])

                    return True
                
            message.status = SMSMessage.Status.FAILED
            message.error_message = "No response from gateway"
            message.save(update_fields=['status', 'error_message', 'updated_at'])
            return False

        except Exception as e:
            message.status = SMSMessage.Status.FAILED
            message.error_message = str(e)
            message.metadata.update({
                'error_details': {
                    'type': 'Exception',
                    'message': str(e),
                    'failed_at': timezone.now().isoformat()
                }
            })
            message.save(update_fields=['status', 'error_message', 'metadata', 'updated_at'])
            logger.error(f"Error sending SMS: {str(e)}")
            return False

    def send_bulk_messages(self, campaign: Campaign) -> Dict:
        """
        Send messages for a campaign
        Returns: Dictionary with success/failure counts
        """
        results = {
            'total': 0,
            'sent': 0,
            'failed': 0,
            'errors': []
        }

        # Get all pending messages for this campaign
        messages = SMSMessage.objects.filter(
            campaign=campaign,
            status=SMSMessage.Status.PENDING
        )

        results['total'] = messages.count()

        for message in messages:
            if self.send_single_sms(message):
                results['sent'] += 1
            else:
                results['failed'] += 1
                results['errors'].append({
                    'recipient': message.recipient,
                    'error': message.error_message
                })

        # Update campaign status
        if results['failed'] == results['total']:
            campaign.status = Campaign.Status.FAILED
        elif results['sent'] == results['total']:
            campaign.status = Campaign.Status.COMPLETED
        else:
            campaign.status = Campaign.Status.PROCESSING

        campaign.metadata.update({
            'send_results': results,
            'completed_at': timezone.now().isoformat()
        })
        campaign.save(update_fields=['status', 'metadata', 'updated_at'])

        return results

    def check_delivery_status(self, message_id: str) -> Dict:
        """
        Check delivery status of a message
        Returns: Dictionary with status details
        """
        try:
            result = self.sms.fetch_messages(last_received_id=message_id)
            return {
                'status': 'success',
                'data': result
            }
        except Exception as e:
            logger.error(f"Error checking message status: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

class TemplateVerificationService:
    """Service for verifying and validating message templates"""

    # Common fraud-related keywords
    FRAUD_KEYWORDS = [
        'account suspended', 'bank account', 'credit card', 'verify account',
        'urgent action', 'win', 'winner', 'prize', 'lottery', 'inheritance',
        'investment opportunity', 'make money', 'get rich', 'password',
        'security code', 'pin number', 'social security', 'free gift',
        'limited time', 'act now', 'click here', 'login details'
    ]

    # Spam trigger words
    SPAM_TRIGGERS = [
        '100% free', 'best price', 'cheap', 'discount', 'fast cash',
        'incredible deal', 'lowest price', 'money back', 'no cost',
        'only today', 'special promotion', 'unlimited', 'what are you waiting for',
        'while supplies last', 'won\'t believe your eyes', 'buy now'
    ]

    def __init__(self):
        """Initialize the service with required NLP models"""
        try:
            self.nlp = spacy.load('en_core_web_sm')
        except:
            self.nlp = None

    def verify_template(self, template: MessageTemplate) -> Tuple[bool, str, Dict]:
        """
        Verify a message template for compliance and content safety
        Returns: (is_approved, rejection_reason, metadata)
        """
        content = template.content.lower()
        metadata = {
            'checks_performed': [],
            'risk_score': 0.0,
            'flagged_content': []
        }

        # Check for fraud keywords
        fraud_matches = self._check_fraud_keywords(content)
        if fraud_matches:
            metadata['flagged_content'].extend(fraud_matches)
            metadata['risk_score'] += 0.4
            metadata['checks_performed'].append('fraud_keywords')

        # Check for spam triggers
        spam_matches = self._check_spam_triggers(content)
        if spam_matches:
            metadata['flagged_content'].extend(spam_matches)
            metadata['risk_score'] += 0.3
            metadata['checks_performed'].append('spam_triggers')

        # Check for profanity
        profanity_score = self._check_profanity(content)
        metadata['profanity_score'] = profanity_score
        metadata['checks_performed'].append('profanity')
        if profanity_score > 0.7:
            metadata['risk_score'] += 0.5

        # Perform sentiment analysis
        sentiment = self._analyze_sentiment(content)
        metadata['sentiment'] = sentiment
        metadata['checks_performed'].append('sentiment')
        if sentiment['polarity'] < -0.5:
            metadata['risk_score'] += 0.2

        # Check template variables
        var_check = self._validate_template_variables(content)
        metadata['variable_check'] = var_check
        metadata['checks_performed'].append('variables')

        # Make approval decision
        is_approved = metadata['risk_score'] < 0.7
        rejection_reason = self._generate_rejection_reason(metadata) if not is_approved else None

        return is_approved, rejection_reason, metadata

    def _check_fraud_keywords(self, content: str) -> List[str]:
        """Check for presence of fraud-related keywords"""
        matches = []
        for keyword in self.FRAUD_KEYWORDS:
            if keyword in content:
                matches.append(keyword)
        return matches

    def _check_spam_triggers(self, content: str) -> List[str]:
        """Check for presence of spam trigger words"""
        matches = []
        for trigger in self.SPAM_TRIGGERS:
            if trigger in content:
                matches.append(trigger)
        return matches

    def _check_profanity(self, content: str) -> float:
        """Check content for profanity using ML model"""
        try:
            # Using profanity-check library
            return float(predict_prob([content])[0])
        except:
            # Fallback to basic word matching if ML fails
            profane_words = set(['profanity', 'words', 'here'])
            words = set(content.split())
            profanity_ratio = len(words.intersection(profane_words)) / len(words)
            return profanity_ratio

    def _analyze_sentiment(self, content: str) -> Dict:
        """Analyze sentiment of the content"""
        try:
            blob = TextBlob(content)
            return {
                'polarity': blob.sentiment.polarity,
                'subjectivity': blob.sentiment.subjectivity
            }
        except:
            return {'polarity': 0, 'subjectivity': 0}

    def _validate_template_variables(self, content: str) -> Dict:
        """Validate template variable syntax and usage"""
        # Find all variables in the format {variable_name}
        variables = re.findall(r'\{([^}]+)\}', content)
        
        return {
            'variables_found': variables,
            'count': len(variables),
            'is_valid': all(self._is_valid_variable_name(var) for var in variables)
        }

    def _is_valid_variable_name(self, variable: str) -> bool:
        """Check if a variable name is valid"""
        return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', variable))

    def _generate_rejection_reason(self, metadata: Dict) -> str:
        """Generate a human-readable rejection reason based on metadata"""
        reasons = []
        
        if metadata.get('flagged_content'):
            reasons.append(f"Contains potentially problematic content: {', '.join(metadata['flagged_content'])}")
        
        if metadata.get('profanity_score', 0) > 0.7:
            reasons.append("Contains inappropriate language")
        
        if metadata.get('sentiment', {}).get('polarity', 0) < -0.5:
            reasons.append("Contains overly negative content")
        
        if not metadata.get('variable_check', {}).get('is_valid', True):
            reasons.append("Contains invalid template variables")
        
        return " | ".join(reasons) if reasons else "Content does not meet guidelines"

    def process_template(self, template: MessageTemplate) -> MessageTemplate:
        """Process a template and update its verification status"""
        is_approved, rejection_reason, metadata = self.verify_template(template)
        
        if is_approved:
            template.verification_status = MessageTemplate.VerificationStatus.APPROVED
            template.rejection_reason = None
        else:
            if metadata['risk_score'] > 0.9:
                template.verification_status = MessageTemplate.VerificationStatus.REJECTED
            else:
                template.verification_status = MessageTemplate.VerificationStatus.FLAGGED
            template.rejection_reason = rejection_reason
        
        template.metadata.update({
            'verification_metadata': metadata,
            'last_verified_at': str(timezone.now())
        })
        template.save()
        
        return template

    @staticmethod
    def contains_profanity(text: str) -> bool:
        """
        Check if the given text contains profanity.
        
        Args:
            text (str): The text to check for profanity
            
        Returns:
            bool: True if profanity is detected, False otherwise
        """
        if HAS_PROFANITY_CHECK:
            # Use the profanity_check library if available
            return bool(predict_prob([text])[0] > 0.5)
        else:
            # Fallback to basic word matching
            text_lower = text.lower()
            return any(word in text_lower for word in BASIC_PROFANE_WORDS)

    @staticmethod
    def verify_template(template_text: str, variables: Dict[str, str] = None) -> Tuple[bool, List[str]]:
        """
        Verify a message template for various criteria.
        
        Args:
            template_text (str): The template text to verify
            variables (Dict[str, str], optional): Variables used in the template
            
        Returns:
            Tuple[bool, List[str]]: (is_valid, list_of_errors)
        """
        errors = []
        
        # Check template length
        max_length = getattr(settings, 'MAX_TEMPLATE_LENGTH', 1000)
        if len(template_text) > max_length:
            errors.append(f"Template exceeds maximum length of {max_length} characters")

        # Check for profanity
        if TemplateVerificationService.contains_profanity(template_text):
            errors.append("Template contains inappropriate language")

        # Validate variable placeholders
        if variables:
            # Check if all required variables are provided
            required_vars = re.findall(r'\{(\w+)\}', template_text)
            for var in required_vars:
                if var not in variables:
                    errors.append(f"Missing required variable: {var}")

            # Check maximum number of variables
            max_vars = getattr(settings, 'MAX_VARIABLES_PER_TEMPLATE', 10)
            if len(variables) > max_vars:
                errors.append(f"Template exceeds maximum number of variables ({max_vars})")

        return len(errors) == 0, errors

    @staticmethod
    def format_template(template: MessageTemplate, variables: Dict[str, str]) -> str:
        """
        Format a template with the provided variables.
        
        Args:
            template (MessageTemplate): The template to format
            variables (Dict[str, str]): Variables to use in formatting
            
        Returns:
            str: The formatted message
        """
        try:
            return template.content.format(**variables)
        except KeyError as e:
            raise ValueError(f"Missing required variable: {str(e)}")
        except Exception as e:
            raise ValueError(f"Error formatting template: {str(e)}") 