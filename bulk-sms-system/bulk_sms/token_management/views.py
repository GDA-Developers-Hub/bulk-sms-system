from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import SubscriptionPlan, UserSubscription, TokenTransaction, TokenPricing
from .serializers import (
    SubscriptionPlanSerializer, UserSubscriptionSerializer,
    TokenTransactionSerializer, TokenPricingSerializer
)
from .services import TokenManagementService

class SubscriptionViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing subscription plans
    """
    queryset = SubscriptionPlan.objects.filter(is_active=True)
    serializer_class = SubscriptionPlanSerializer
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Get available subscription plans",
        responses={200: SubscriptionPlanSerializer(many=True)}
    )
    def list(self, request):
        """List all active subscription plans"""
        plans = self.get_queryset()
        serializer = self.get_serializer(plans, many=True)
        return Response(serializer.data)
    
    @swagger_auto_schema(
        operation_description="Get user's current subscription",
        responses={200: UserSubscriptionSerializer()}
    )
    @action(detail=False, methods=['get'])
    def current(self, request):
        """Get current user's subscription"""
        subscription = UserSubscription.objects.filter(
            user=request.user,
            status='active',
            end_date__gt=timezone.now()
        ).first()
        
        if not subscription:
            return Response(
                {"detail": "No active subscription found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = UserSubscriptionSerializer(subscription)
        return Response(serializer.data)
    
    @swagger_auto_schema(
        operation_description="Change subscription plan",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'plan': openapi.Schema(type=openapi.TYPE_STRING),
                'auto_renew': openapi.Schema(type=openapi.TYPE_BOOLEAN),
            },
            required=['plan']
        ),
        responses={200: UserSubscriptionSerializer()}
    )
    @action(detail=False, methods=['post'])
    def change_plan(self, request):
        """Change subscription plan"""
        plan_type = request.data.get('plan')
        auto_renew = request.data.get('auto_renew', False)
        
        try:
            # Get the new plan
            new_plan = SubscriptionPlan.objects.get(
                plan_type=plan_type,
                is_active=True
            )
            
            # Create or update subscription
            subscription, created = UserSubscription.objects.update_or_create(
                user=request.user,
                status='active',
                defaults={
                    'plan': new_plan,
                    'start_date': timezone.now(),
                    'end_date': timezone.now() + timezone.timedelta(days=new_plan.validity_days),
                    'auto_renew': auto_renew
                }
            )
            
            serializer = UserSubscriptionSerializer(subscription)
            return Response(serializer.data)
            
        except SubscriptionPlan.DoesNotExist:
            return Response(
                {"detail": "Invalid plan type"},
                status=status.HTTP_400_BAD_REQUEST
            )

class TokenViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing tokens
    """
    serializer_class = TokenTransactionSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Return only the authenticated user's transactions"""
        return TokenTransaction.objects.filter(user=self.request.user)
    
    @swagger_auto_schema(
        operation_description="Get token balance and subscription info",
        responses={200: openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'balance': openapi.Schema(type=openapi.TYPE_INTEGER),
                'subscription': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'plan': openapi.Schema(type=openapi.TYPE_STRING),
                        'expiry': openapi.Schema(type=openapi.TYPE_STRING),
                        'status': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            }
        )}
    )
    @action(detail=False, methods=['get'])
    def balance(self, request):
        """Get user's token balance"""
        balance_info = TokenManagementService.get_token_balance(request.user)
        return Response(balance_info)
    
    @swagger_auto_schema(
        operation_description="Purchase tokens",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'package': openapi.Schema(type=openapi.TYPE_STRING),
                'payment_method': openapi.Schema(type=openapi.TYPE_STRING),
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['package']
        ),
        responses={200: TokenTransactionSerializer()}
    )
    @action(detail=False, methods=['post'])
    def purchase(self, request):
        """Purchase tokens"""
        try:
            result = TokenManagementService.purchase_tokens(
                user=request.user,
                package_type=request.data.get('package'),
                payment_method=request.data.get('payment_method', 'mpesa'),
                phone_number=request.data.get('phone_number')
            )
            return Response(result)
            
        except ValueError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @swagger_auto_schema(
        operation_description="Get token pricing tiers",
        responses={200: TokenPricingSerializer(many=True)}
    )
    @action(detail=False, methods=['get'])
    def pricing(self, request):
        """Get token pricing tiers"""
        pricing = TokenPricing.objects.filter(is_active=True)
        serializer = TokenPricingSerializer(pricing, many=True)
        return Response(serializer.data)
    
    @swagger_auto_schema(
        operation_description="Get token transaction history",
        responses={200: TokenTransactionSerializer(many=True)}
    )
    @action(detail=False, methods=['get'])
    def history(self, request):
        """Get token transaction history"""
        transactions = self.get_queryset().order_by('-created_at')
        page = self.paginate_queryset(transactions)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
            
        serializer = self.get_serializer(transactions, many=True)
        return Response(serializer.data) 