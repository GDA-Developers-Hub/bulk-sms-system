from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .services import TokenManagementService

User = get_user_model()

@receiver(post_save, sender=User)
def create_demo_subscription(sender, instance, created, **kwargs):
    """Create demo subscription for new users"""
    if created:
        try:
            TokenManagementService.create_demo_subscription(instance)
        except Exception as e:
            # Log the error but don't prevent user creation
            print(f"Error creating demo subscription: {str(e)}") 