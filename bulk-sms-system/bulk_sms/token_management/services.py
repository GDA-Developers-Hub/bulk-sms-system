from django.utils import timezone
from django.db import transaction
from django.conf import settings
from datetime import timedelta
import uuid
from django.core.cache import cache
from django.db.models import Sum, F
from decimal import Decimal

from .models import SubscriptionPlan, UserSubscription, TokenTransaction, TokenPricing
from utils.mpesa import MPesaClient

class TokenManagementService:
    @staticmethod
    def create_demo_subscription(user):
        """Create a demo subscription for new users"""
        try:
            # Get demo plan
            demo_plan = SubscriptionPlan.objects.get(plan_type='demo')
            
            # Calculate dates
            start_date = timezone.now()
            end_date = start_date + timedelta(days=demo_plan.validity_days)
            
            # Create subscription
            subscription = UserSubscription.objects.create(
                user=user,
                plan=demo_plan,
                start_date=start_date,
                end_date=end_date,
                metadata={
                    'is_demo': True,
                    'tokens_used': 0
                }
            )
            
            # Add free tokens
            TokenManagementService.add_tokens(
                user=user,
                tokens=demo_plan.tokens,
                transaction_type='bonus',
                reference=f"DEMO-{uuid.uuid4().hex[:8]}",
                metadata={
                    'subscription_id': str(subscription.id),
                    'reason': 'Demo plan free tokens'
                }
            )
            
            return subscription
            
        except SubscriptionPlan.DoesNotExist:
            raise ValueError("Demo plan not found")

    @staticmethod
    def purchase_tokens(user, package_type, payment_method='mpesa', phone_number=None):
        """Purchase tokens for a user"""
        try:
            # Get subscription plan
            plan = SubscriptionPlan.objects.get(plan_type=package_type, is_active=True)
            
            # Get or create user subscription
            subscription = UserSubscription.objects.filter(
                user=user,
                status='active'
            ).first()
            
            # Create token transaction
            reference = f"TKN-{uuid.uuid4().hex[:8]}"
            transaction = TokenTransaction.objects.create(
                user=user,
                transaction_type='purchase',
                tokens=plan.tokens,
                amount=plan.price,
                reference=reference,
                metadata={
                    'plan_type': package_type,
                    'payment_method': payment_method
                }
            )
            
            # Handle M-Pesa payment
            if payment_method == 'mpesa':
                phone = phone_number or user.phone_number
                if not phone:
                    raise ValueError("Phone number is required for M-Pesa payment")
                
                mpesa = MPesaClient()
                payment_response = mpesa.initiate_stk_push(
                    phone_number=phone,
                    amount=float(plan.price),
                    account_reference=reference,
                    transaction_desc=f"Token purchase: {plan.tokens} SMS tokens"
                )
                
                # Update transaction with payment details
                transaction.metadata.update({
                    'checkout_request_id': payment_response.get('checkout_request_id'),
                    'mpesa_response': payment_response
                })
                transaction.save()
                
                return {
                    'transaction_id': str(transaction.id),
                    'reference': reference,
                    'status': 'pending',
                    'message': 'Please complete payment on your phone'
                }
            
            return {
                'transaction_id': str(transaction.id),
                'reference': reference,
                'status': 'pending',
                'message': 'Payment initiated'
            }
            
        except SubscriptionPlan.DoesNotExist:
            raise ValueError(f"Invalid package type: {package_type}")

    @staticmethod
    def validate_tokens_for_message(user, message_length, recipients_count):
        """Validate if user has enough tokens to send message"""
        # Calculate required tokens (1 token per 160 characters per recipient)
        segments = max(1, message_length // 160 + (1 if message_length % 160 > 0 else 0))
        required_tokens = segments * recipients_count
        
        # Get user's active subscription
        subscription = UserSubscription.objects.filter(
            user=user,
            status='active',
            end_date__gt=timezone.now()
        ).first()
        
        if not subscription:
            raise ValueError("No active subscription found")
        
        # Check token balance
        if user.tokens_balance < required_tokens:
            raise ValueError(
                f"Insufficient tokens. Required: {required_tokens}, Available: {user.tokens_balance}"
            )
        
        return required_tokens

    @staticmethod
    @transaction.atomic
    def deduct_tokens(user, tokens_used, message_id=None):
        """Deduct tokens after successful message sending"""
        if user.tokens_balance < tokens_used:
            raise ValueError("Insufficient tokens")
        
        # Create usage transaction
        TokenTransaction.objects.create(
            user=user,
            transaction_type='usage',
            tokens=-tokens_used,
            reference=f"USE-{uuid.uuid4().hex[:8]}",
            status='completed',
            metadata={
                'message_id': message_id,
                'previous_balance': user.tokens_balance
            }
        )
        
        # Update user's token balance
        user.tokens_balance -= tokens_used
        user.save(update_fields=['tokens_balance', 'updated_at'])
        
        # Check low balance notification
        if user.tokens_balance <= user.metadata.get('preferences', {}).get('notifications', {}).get('low_balance', 0):
            # TODO: Send low balance notification
            pass

    @staticmethod
    @transaction.atomic
    def add_tokens(user, tokens, transaction_type='purchase', reference=None, metadata=None):
        """Add tokens to user's balance"""
        if tokens <= 0:
            raise ValueError("Token amount must be positive")
        
        # Create transaction
        TokenTransaction.objects.create(
            user=user,
            transaction_type=transaction_type,
            tokens=tokens,
            reference=reference or f"ADD-{uuid.uuid4().hex[:8]}",
            status='completed',
            metadata=metadata or {
                'previous_balance': user.tokens_balance
            }
        )
        
        # Update user's token balance
        user.tokens_balance += tokens
        user.save(update_fields=['tokens_balance', 'updated_at'])

    @staticmethod
    def get_token_balance(user):
        """Get user's current token balance and subscription info"""
        subscription = UserSubscription.objects.filter(
            user=user,
            status='active',
            end_date__gt=timezone.now()
        ).first()
        
        return {
            'balance': user.tokens_balance,
            'subscription': {
                'plan': subscription.plan.plan_type if subscription else None,
                'expiry': subscription.end_date if subscription else None,
                'status': subscription.status if subscription else 'inactive'
            }
        }

    @staticmethod
    def transfer_tokens(from_user, to_user, tokens, reason=None):
        """Transfer tokens between users"""
        if from_user.tokens_balance < tokens:
            raise ValueError("Insufficient tokens for transfer")
        
        if tokens <= 0:
            raise ValueError("Token amount must be positive")
        
        with transaction.atomic():
            # Generate reference for the transaction pair
            ref_base = f"TRF-{uuid.uuid4().hex[:8]}"
            
            # Deduct tokens from sender
            TokenTransaction.objects.create(
                user=from_user,
                transaction_type='usage',
                tokens=-tokens,
                reference=f"{ref_base}-OUT",
                status='completed',
                metadata={
                    'transfer_to': str(to_user.id),
                    'reason': reason or 'Token transfer'
                }
            )
            
            # Add tokens to receiver
            TokenTransaction.objects.create(
                user=to_user,
                transaction_type='bonus',
                tokens=tokens,
                reference=f"{ref_base}-IN",
                status='completed',
                metadata={
                    'transfer_from': str(from_user.id),
                    'reason': reason or 'Token transfer'
                }
            )
            
            # Update balances
            from_user.tokens_balance -= tokens
            to_user.tokens_balance += tokens
            from_user.save(update_fields=['tokens_balance', 'updated_at'])
            to_user.save(update_fields=['tokens_balance', 'updated_at'])

    @staticmethod
    def get_token_usage_stats(user, days=30):
        """Get token usage statistics for a user"""
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        # Get daily usage
        daily_usage = TokenTransaction.objects.filter(
            user=user,
            transaction_type='usage',
            created_at__range=(start_date, end_date)
        ).values('created_at__date').annotate(
            total_tokens=Sum('tokens')
        ).order_by('created_at__date')
        
        # Get usage by transaction type
        usage_by_type = TokenTransaction.objects.filter(
            user=user,
            created_at__range=(start_date, end_date)
        ).values('transaction_type').annotate(
            total_tokens=Sum('tokens')
        )
        
        # Calculate burn rate (average daily token consumption)
        total_usage = abs(sum(day['total_tokens'] or 0 for day in daily_usage))
        burn_rate = total_usage / days if days > 0 else 0
        
        # Estimate days remaining based on current balance and burn rate
        days_remaining = user.tokens_balance / burn_rate if burn_rate > 0 else float('inf')
        
        return {
            'daily_usage': list(daily_usage),
            'usage_by_type': list(usage_by_type),
            'burn_rate': burn_rate,
            'days_remaining': days_remaining,
            'total_usage': total_usage
        }

    @staticmethod
    def bulk_add_tokens(users, tokens, reason=None):
        """Add tokens to multiple users at once"""
        if tokens <= 0:
            raise ValueError("Token amount must be positive")
        
        with transaction.atomic():
            for user in users:
                TokenManagementService.add_tokens(
                    user=user,
                    tokens=tokens,
                    transaction_type='bonus',
                    reference=f"BULK-{uuid.uuid4().hex[:8]}",
                    metadata={'reason': reason or 'Bulk token addition'}
                )

    @staticmethod
    def get_token_alerts(user):
        """Get token balance alerts and recommendations"""
        # Get user's average daily usage
        stats = TokenManagementService.get_token_usage_stats(user, days=7)
        burn_rate = stats['burn_rate']
        
        alerts = []
        recommendations = []
        
        # Check low balance
        if user.tokens_balance < burn_rate * 3:  # Less than 3 days worth of tokens
            alerts.append({
                'type': 'low_balance',
                'message': f'Low token balance. At current usage, tokens will last {stats["days_remaining"]:.1f} days.'
            })
            
            # Recommend suitable package
            suitable_plan = SubscriptionPlan.objects.filter(
                tokens__gte=burn_rate * 30,  # At least a month's worth
                is_active=True
            ).order_by('tokens').first()
            
            if suitable_plan:
                recommendations.append({
                    'type': 'plan_upgrade',
                    'message': f'Consider upgrading to {suitable_plan.name} plan for {suitable_plan.tokens} tokens.'
                })
        
        # Check for unusual usage patterns
        recent_usage = stats['daily_usage'][-3:]  # Last 3 days
        if recent_usage:
            avg_usage = sum(day['total_tokens'] or 0 for day in recent_usage) / len(recent_usage)
            if avg_usage > burn_rate * 2:  # Usage spike
                alerts.append({
                    'type': 'usage_spike',
                    'message': 'Unusual increase in token usage detected.'
                })
        
        return {
            'alerts': alerts,
            'recommendations': recommendations
        }

    @staticmethod
    def get_subscription_insights(user):
        """Get insights about user's subscription and token usage patterns"""
        current_subscription = UserSubscription.objects.filter(
            user=user,
            status='active',
            end_date__gt=timezone.now()
        ).first()
        
        if not current_subscription:
            return {'status': 'no_active_subscription'}
        
        # Get usage statistics
        stats = TokenManagementService.get_token_usage_stats(user)
        
        # Calculate subscription efficiency
        plan_tokens = current_subscription.plan.tokens
        days_elapsed = (timezone.now() - current_subscription.start_date).days
        total_days = (current_subscription.end_date - current_subscription.start_date).days
        expected_daily_usage = plan_tokens / total_days if total_days > 0 else 0
        actual_daily_usage = stats['burn_rate']
        
        efficiency = (actual_daily_usage / expected_daily_usage * 100) if expected_daily_usage > 0 else 0
        
        return {
            'subscription': {
                'plan': current_subscription.plan.name,
                'days_remaining': (current_subscription.end_date - timezone.now()).days,
                'tokens_remaining': user.tokens_balance,
            },
            'usage_efficiency': {
                'expected_daily_usage': expected_daily_usage,
                'actual_daily_usage': actual_daily_usage,
                'efficiency_percentage': efficiency,
            },
            'recommendations': TokenManagementService.get_token_alerts(user)['recommendations']
        } 