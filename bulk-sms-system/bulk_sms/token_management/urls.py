from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import SubscriptionViewSet, TokenViewSet

router = DefaultRouter()
router.register(r'subscriptions', SubscriptionViewSet, basename='subscription')
router.register(r'tokens', TokenViewSet, basename='token')

urlpatterns = [
    path('', include(router.urls)),
] 