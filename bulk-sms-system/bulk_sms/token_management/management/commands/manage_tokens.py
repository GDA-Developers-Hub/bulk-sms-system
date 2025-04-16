from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from token_management.models import TokenTransaction, UserSubscription
from token_management.services import TokenManagementService
from datetime import datetime, timedelta

User = get_user_model()

class Command(BaseCommand):
    help = 'Manage token operations like adding tokens, checking balances, and cleaning up expired transactions'

    def add_arguments(self, parser):
        parser.add_argument('action', type=str, choices=['add', 'check', 'cleanup', 'expire'])
        parser.add_argument('--user', type=str, help='User email or company name')
        parser.add_argument('--tokens', type=int, help='Number of tokens to add')
        parser.add_argument('--days', type=int, help='Number of days for cleanup/expiry')
        parser.add_argument('--reason', type=str, help='Reason for adding tokens')

    def handle(self, *args, **options):
        action = options['action']
        
        if action == 'add':
            if not options['user'] or not options['tokens']:
                raise CommandError('--user and --tokens are required for add action')
            
            try:
                user = User.objects.get(email=options['user'])
                TokenManagementService.add_tokens(
                    user=user,
                    tokens=options['tokens'],
                    transaction_type='bonus',
                    reference=f"CMD-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    metadata={'reason': options.get('reason', 'Manual addition via command')}
                )
                self.stdout.write(self.style.SUCCESS(
                    f'Successfully added {options["tokens"]} tokens to {user.email}'
                ))
            except User.DoesNotExist:
                raise CommandError(f'User {options["user"]} does not exist')
        
        elif action == 'check':
            if not options['user']:
                raise CommandError('--user is required for check action')
            
            try:
                user = User.objects.get(email=options['user'])
                balance_info = TokenManagementService.get_token_balance(user)
                self.stdout.write(self.style.SUCCESS(
                    f'Token balance for {user.email}:\n'
                    f'Current balance: {balance_info["balance"]}\n'
                    f'Subscription: {balance_info["subscription"]["plan"]}\n'
                    f'Expiry: {balance_info["subscription"]["expiry"]}'
                ))
            except User.DoesNotExist:
                raise CommandError(f'User {options["user"]} does not exist')
        
        elif action == 'cleanup':
            days = options.get('days', 30)
            cutoff_date = datetime.now() - timedelta(days=days)
            
            # Clean up completed/failed transactions older than cutoff date
            deleted_count = TokenTransaction.objects.filter(
                created_at__lt=cutoff_date,
                status__in=['completed', 'failed']
            ).delete()[0]
            
            self.stdout.write(self.style.SUCCESS(
                f'Cleaned up {deleted_count} old transactions'
            ))
        
        elif action == 'expire':
            days = options.get('days', 0)
            cutoff_date = datetime.now() - timedelta(days=days)
            
            # Expire subscriptions
            expired_count = UserSubscription.objects.filter(
                end_date__lt=cutoff_date,
                status='active'
            ).update(status='expired')
            
            self.stdout.write(self.style.SUCCESS(
                f'Expired {expired_count} subscriptions'
            )) 