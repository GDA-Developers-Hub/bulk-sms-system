# Bulk SMS System API Documentation

## System Overview

The Bulk SMS System is a token-based platform that allows businesses to send SMS messages through Africa's Talking. The system includes subscription plans, token management, and detailed delivery tracking.

### Pricing Structure
- Buying Price per SMS: KES 0.30 - 0.50
- Selling Price per SMS: KES 0.70 - 1.50
- Profit Margin per SMS: KES 0.40 - 1.00

### Subscription Plans

#### Demo Plan (Free Tier)
- 5 free SMS tokens
- Valid for 3 days
- Basic features (template library)
- No auto-renewal

#### Standard Plans
1. **Starter Package**
   - 1,000 tokens
   - KES 1,000 (KES 1.00 per SMS)
   - Valid for 30 days

2. **Business Package**
   - 10,000 tokens
   - KES 9,000 (KES 0.90 per SMS)
   - Valid for 30 days

3. **Enterprise Package**
   - 50,000 tokens
   - KES 40,000 (KES 0.80 per SMS)
   - Valid for 30 days

## Deployment on Railway

This guide will help you test and deploy the Bulk SMS System on Railway.

### Prerequisites

- A Railway account
- Git repository with your code
- PostgreSQL database
- Redis (for Celery task queue)
- Environment variables configured in Railway

### Environment Variables

Make sure to set these environment variables in your Railway project:

```
DEBUG=False
SECRET_KEY=your_secret_key
DATABASE_URL=postgresql://user:password@host:port/dbname
REDIS_URL=redis://user:password@host:port

# Africa's Talking credentials
AFRICASTALKING_API_KEY=your_api_key
AFRICASTALKING_USERNAME=your_username
AFRICASTALKING_SENDER_ID=your_sender_id

# Twilio credentials (if using)
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE_NUMBER=your_phone_number

# CORS settings
ALLOWED_HOSTS=.railway.app,your-domain.com
CORS_ALLOWED_ORIGINS=https://your-frontend-domain.com

# Email settings
EMAIL_HOST=smtp.provider.com
EMAIL_PORT=587
EMAIL_HOST_USER=your_email@example.com
EMAIL_HOST_PASSWORD=your_email_password
EMAIL_USE_TLS=True
DEFAULT_FROM_EMAIL=your_email@example.com

# Frontend URL for email verification
FRONTEND_URL=https://your-frontend-domain.com
```

## API Endpoints

### Authentication Endpoints

#### Register a new user

**Endpoint:** `POST /api/v1/register/`

**Required Fields:**
```json
{
  "company_name": "Your Company Name",
  "email": "your-email@example.com",
  "phone_number": "+2547XXXXXXXX",
  "password": "YourSecurePassword123",
  "confirm_password": "YourSecurePassword123"
}
```

#### Login

**Endpoint:** `POST /api/v1/login/`

**Required Fields:**
```json
{
  "company_name": "Your Company Name",
  "password": "YourSecurePassword123"
}
```

**Response will include:**
- Authentication tokens (access and refresh)
- User details

#### Email Verification Request

**Endpoint:** `POST /api/v1/email/verify-request/`

**Required Fields:**
```json
{
  "email": "your-email@example.com"
}
```

#### Email Verification Confirm

**Endpoint:** `POST /api/v1/email/verify-confirm/`

**Required Fields:**
```json
{
  "token": "verification_token_from_email"
}
```

#### Reset Password Request

**Endpoint:** `POST /api/v1/reset-password/request/`

**Required Fields:**
```json
{
  "email": "your-email@example.com"
}
```

#### Reset Password Confirm

**Endpoint:** `POST /api/v1/reset-password/confirm/`

**Required Fields:**
```json
{
  "token": "reset_token_from_email",
  "new_password": "NewSecurePassword123",
  "confirm_password": "NewSecurePassword123"
}
```

#### Change Password

**Endpoint:** `POST /api/v1/change-password/`  
**Authentication:** Required

**Required Fields:**
```json
{
  "old_password": "YourCurrentPassword",
  "new_password": "YourNewPassword123",
  "confirm_password": "YourNewPassword123"
}
```

#### Logout

**Endpoint:** `POST /api/v1/logout/`  
**Authentication:** Required

**Required Fields:**
```json
{
  "refresh": "your_refresh_token"
}
```

### User Management

#### Get User Profile

**Endpoint:** `GET /api/v1/profile/`  
**Authentication:** Required

**Response:**
```json
{
  "user_id": "uuid",
  "company_name": "Company Name",
  "email": "email@example.com",
  "phone_number": "+254XXXXXXXXX",
  "tokens_balance": 100,
  "metadata": {
    "api": {
      "key": "api_xxxxx",
      "secret": "secret_xxxxx",
      "allowed_ips": []
    },
    "business": {
      "size": "Not specified",
      "address": {
        "city": "Nairobi",
        "country": "Kenya"
      },
      "industry": "Other"
    },
    "preferences": {
      "timezone": "Africa/Nairobi",
      "notifications": {
        "low_balance": 1000,
        "delivery_reports": true
      },
      "default_sender_id": "INFO"
    },
    "subscription": {
      "plan": "demo",
      "price": 0,
      "currency": "KES",
      "end_date": "2025-04-17T09:53:30.879Z",
      "features": [
        "template-library",
        "5-free-sms"
      ],
      "auto_renew": false,
      "start_date": "2025-04-14T09:53:30.879Z"
    }
  }
}
```

### Token Management

#### Purchase Tokens

**Endpoint:** `POST /api/v1/tokens/purchase/`  
**Authentication:** Required

**Required Fields:**
```json
{
  "package": "starter",
  "payment_method": "mpesa",
  "phone_number": "+254XXXXXXXXX"
}
```

**Response:**
```json
{
  "transaction_id": "uuid",
  "amount": 1000,
  "tokens": 1000,
  "status": "pending",
  "checkout_request_id": "ws_CO_123456789",
  "message": "Please complete payment on your phone"
}
```

#### Check Token Balance

**Endpoint:** `GET /api/v1/tokens/balance/`  
**Authentication:** Required

**Response:**
```json
{
  "balance": 100,
  "last_updated": "2024-04-14T10:00:00Z",
  "subscription": {
    "plan": "starter",
    "expiry": "2024-05-14T10:00:00Z"
  }
}
```

### Subscription Management

#### Get Available Plans

**Endpoint:** `GET /api/v1/subscriptions/plans/`  
**Authentication:** Required

**Response:**
```json
{
  "plans": [
    {
      "id": "demo",
      "name": "Demo Plan",
      "price": 0,
      "tokens": 5,
      "validity_days": 3,
      "features": [
        "template-library",
        "5-free-sms"
      ]
    },
    {
      "id": "starter",
      "name": "Starter Package",
      "price": 1000,
      "tokens": 1000,
      "validity_days": 30,
      "features": [
        "template-library",
        "delivery-reports",
        "api-access"
      ]
    }
  ]
}
```

#### Change Subscription Plan

**Endpoint:** `POST /api/v1/subscriptions/change/`  
**Authentication:** Required

**Required Fields:**
```json
{
  "plan": "starter",
  "auto_renew": false
}
```

### SMS Sending

#### Send Bulk SMS

**Endpoint:** `POST /api/v1/messages/send-bulk/`  
**Authentication:** Required

**Required Fields:**
```json
{
  "recipients": ["+254XXXXXXXXX"],
  "message": "Your message content",
  "sender_id": "INFO",
  "schedule_time": "2024-04-15T10:00:00Z" // Optional
}
```

**Response:**
```json
{
  "message_id": "uuid",
  "recipients_count": 1,
  "tokens_used": 1,
  "tokens_balance": 99,
  "status": "queued",
  "cost": {
    "amount": 1,
    "currency": "KES"
  }
}
```

### Delivery Reports

#### Get Message Status

**Endpoint:** `GET /api/v1/messages/{message_id}/status/`  
**Authentication:** Required

**Response:**
```json
{
  "message_id": "uuid",
  "status": "delivered",
  "sent_at": "2024-04-14T10:00:00Z",
  "delivered_at": "2024-04-14T10:00:05Z",
  "recipient": "+254XXXXXXXXX",
  "cost": {
    "amount": 1,
    "currency": "KES"
  }
}
```

## Token Validation Logic

1. **New User Registration**:
   - Automatically assigned Demo Plan
   - 5 free tokens loaded
   - 3-day validity period
   - Token metadata added to user profile

2. **Token Purchase Flow**:
   ```python
   def process_token_purchase(user, package):
       # Get package details
       package_details = SMS_PACKAGES.get(package)
       if not package_details:
           raise InvalidPackage()
           
       # Calculate cost
       amount = package_details['price']
       tokens = package_details['tokens']
       
       # Create payment record
       payment = create_payment_record(
           user=user,
           amount=amount,
           tokens=tokens,
           package=package
       )
       
       # Initiate M-Pesa payment
       mpesa_response = initiate_mpesa_payment(
           phone=user.phone_number,
           amount=amount,
           account_ref=f"SMS-{payment.id}"
       )
       
       return payment, mpesa_response
   ```

3. **Token Validation Before Sending**:
   ```python
   def validate_tokens_for_message(user, recipients_count):
       # Calculate required tokens
       required_tokens = calculate_required_tokens(
           message_length=len(message),
           recipients_count=recipients_count
       )
       
       # Check user's balance
       if user.tokens_balance < required_tokens:
           raise InsufficientTokens()
           
       # Check subscription validity
       if not is_subscription_valid(user):
           raise SubscriptionExpired()
           
       return required_tokens
   ```

4. **Token Deduction After Sending**:
   ```python
   def deduct_tokens(user, tokens_used):
       user.tokens_balance -= tokens_used
       user.save()
       
       # Check low balance notification
       if user.tokens_balance <= user.metadata['preferences']['notifications']['low_balance']:
           send_low_balance_notification(user)
   ```

## Testing Strategy

1. **Authentication Flow**:
   - Register a new user
   - Verify email
   - Login to receive tokens
   - Test token refresh
   - Test password change
   - Test logout

2. **Contact Management**:
   - Create contact groups
   - Import contacts
   - Verify contacts are properly stored

3. **SMS Campaigns**:
   - Create SMS templates
   - Create a campaign with test contacts
   - Send a campaign to test delivery
   - Check campaign statistics

4. **Payment Flow**:
   - Initiate a test payment
   - Check payment status
   - Verify token balance updates

5. **Webhooks**:
   - Create webhook endpoints
   - Test webhooks with sample events
   - Verify webhook delivery

## Health Check

After deployment, test the health of your application by accessing the root endpoint:

**Endpoint:** `GET /api/`

If the response shows the available endpoints, your API is up and running correctly.

## Common Issues

1. **Database Connectivity**: Ensure the `DATABASE_URL` is correct and the database is accessible from Railway.
   
2. **Redis Connection**: Verify Redis connectivity for Celery tasks.

3. **SMS Gateway**: Test Africa's Talking connectivity by sending a test message.

4. **Webhook Errors**: Ensure your webhook endpoints are publicly accessible.

## Monitoring

Once deployed, monitor your application using:

1. Railway's built-in logs
2. Custom application logs through Django's logging system
3. Database connection pool stats
4. Redis queue length for pending tasks 