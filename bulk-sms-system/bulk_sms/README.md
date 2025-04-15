# SMS Campaign System API Endpoints

Here's a comprehensive list of all endpoints in the SMS Campaign system:

## Authentication Endpoints
- `POST /api/token/` - Obtain JWT token with company name and password
- `POST /api/token/refresh/` - Refresh JWT token
- `POST /api/login/` - Login with company name and password
- `POST /api/logout/` - Logout and blacklist refresh token
- `POST /api/register/` - Register a new user account
- `POST /api/email/verify-request/` - Request email verification token
- `POST /api/email/verify-confirm/` - Confirm email verification with token
- `POST /api/change-password/` - Change user password
- `POST /api/reset-password/request/` - Request password reset
- `POST /api/reset-password/confirm/` - Confirm password reset with token
- `GET/PATCH /api/profile/` - Get or update user profile

## User Management
- `GET /api/users/me/` - Get current user information
- `GET /api/users/` - List all users (admin only)
- `POST /api/users/` - Create a new user (admin only)
- `GET /api/users/{id}/` - Retrieve a specific user (admin only)
- `PUT/PATCH /api/users/{id}/` - Update a specific user (admin only)
- `DELETE /api/users/{id}/` - Delete a specific user (admin only)

## Contact Groups
- `GET /api/groups/` - List all contact groups
- `POST /api/groups/` - Create a new contact group
- `GET /api/groups/{id}/` - Retrieve a specific contact group
- `PUT/PATCH /api/groups/{id}/` - Update a specific contact group
- `DELETE /api/groups/{id}/` - Delete a specific contact group
- `GET /api/groups/{id}/contacts/` - List all contacts in a specific group
- `POST /api/groups/new-group/` - Create a new contact group with validation

## Contacts
- `GET /api/contacts/` - List all contacts in user's groups
- `POST /api/contacts/` - Create a new contact
- `GET /api/contacts/{id}/` - Retrieve a specific contact
- `PUT/PATCH /api/contacts/{id}/` - Update a specific contact
- `DELETE /api/contacts/{id}/` - Delete a specific contact
- `POST /api/contacts/import_contacts/` - Import contacts in bulk
- `GET /api/contacts/export/` - Export contacts from a group
- `POST /api/contacts/add_contact/` - Add a new contact with validation

## SMS Templates
- `GET /api/templates/` - List all SMS templates
- `POST /api/templates/` - Create a new SMS template
- `GET /api/templates/{id}/` - Retrieve a specific template
- `PUT/PATCH /api/templates/{id}/` - Update a specific template
- `DELETE /api/templates/{id}/` - Delete a specific template
- `POST /api/templates/{id}/mark_used/` - Mark a template as used
- `GET /api/templates/categories/` - Get available template categories
- `GET /api/templates/stats/` - Get template statistics

## SMS Campaigns
- `GET /api/campaigns/` - List all SMS campaigns
- `POST /api/campaigns/` - Create a new SMS campaign
- `GET /api/campaigns/{id}/` - Retrieve a specific campaign
- `PUT/PATCH /api/campaigns/{id}/` - Update a specific campaign
- `DELETE /api/campaigns/{id}/` - Delete a specific campaign
- `POST /api/campaigns/{id}/send/` - Initiate sending of a campaign
- `POST /api/campaigns/{id}/cancel/` - Cancel a scheduled campaign
- `GET /api/campaigns/{id}/stats/` - Get statistics for a campaign
- `GET /api/campaigns/{id}/messages/` - Get message details for a campaign
- `POST /api/campaigns/{id}/clone/` - Clone an existing campaign
- `GET /api/campaigns/types/` - Get campaign types
- `GET /api/campaigns/statuses/` - Get campaign statuses

## SMS Messages
- `GET /api/messages/` - List all SMS messages
- `POST /api/messages/` - Create a new SMS message
- `GET /api/messages/{id}/` - Retrieve a specific message
- `PUT/PATCH /api/messages/{id}/` - Update a specific message
- `DELETE /api/messages/{id}/` - Delete a specific message
- `POST /api/messages/quick_send/` - Send a quick SMS message without campaign

## Payments
- `GET /api/payments/` - List all payments
- `POST /api/payments/` - Create a new payment record
- `GET /api/payments/{id}/` - Retrieve a specific payment
- `PUT/PATCH /api/payments/{id}/` - Update a specific payment
- `DELETE /api/payments/{id}/` - Delete a specific payment

## Webhooks
- `GET /api/webhooks/` - List all webhook endpoints
- `POST /api/webhooks/` - Create a new webhook endpoint
- `GET /api/webhooks/{id}/` - Retrieve a specific webhook
- `PUT/PATCH /api/webhooks/{id}/` - Update a specific webhook
- `DELETE /api/webhooks/{id}/` - Delete a specific webhook

Each endpoint follows RESTful principles with appropriate HTTP methods. The endpoints that accept parameters (like IDs) are marked with `{id}`. All endpoints require authentication except for the registration, login, and password reset endpoints.
