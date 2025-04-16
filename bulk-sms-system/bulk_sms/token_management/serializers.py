from rest_framework import serializers
from .models import SubscriptionPlan, UserSubscription, TokenTransaction, TokenPricing

class SubscriptionPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = ['id', 'name', 'plan_type', 'price', 'tokens', 'validity_days', 
                 'features', 'is_active']

class UserSubscriptionSerializer(serializers.ModelSerializer):
    plan_details = SubscriptionPlanSerializer(source='plan', read_only=True)
    
    class Meta:
        model = UserSubscription
        fields = ['id', 'plan', 'plan_details', 'status', 'start_date', 'end_date', 
                 'auto_renew', 'metadata']
        read_only_fields = ['status']

class TokenTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = TokenTransaction
        fields = ['id', 'transaction_type', 'tokens', 'amount', 'status', 
                 'reference', 'metadata', 'created_at']
        read_only_fields = ['status', 'reference']

class TokenPricingSerializer(serializers.ModelSerializer):
    profit_margin = serializers.SerializerMethodField()
    
    class Meta:
        model = TokenPricing
        fields = ['id', 'min_tokens', 'max_tokens', 'selling_price', 'profit_margin']
    
    def get_profit_margin(self, obj):
        """Calculate profit margin percentage"""
        if obj.buying_price > 0:
            margin = ((obj.selling_price - obj.buying_price) / obj.buying_price) * 100
            return round(margin, 2)
        return 0 