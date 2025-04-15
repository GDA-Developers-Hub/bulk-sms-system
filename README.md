# Go Digital Africa Bulk SMS Platform

## Overview
Go Digital Africa Bulk SMS Platform is a comprehensive solution for businesses to manage and send bulk SMS messages to their customers. The platform provides features such as contact management, message scheduling, templates, analytics, and integration capabilities through webhooks and APIs.

## Technology Stack

### Backend
- **Framework**: Django (Python)
- **API**: Django REST Framework
- **SMS Gateway Integration**: Twilio and Africa's Talking
- **Message Queue**: RabbitMQ/Redis for high-volume message processing
- **Authentication**: JWT-based authentication
- **Database**: PostgreSQL for primary data storage
- **Caching**: Redis

### Frontend
- **Framework**: React
- **Styling**: Tailwind CSS
- **State Management**: React Context API / Redux
- **UI Components**: Custom components with Tailwind

### Payment Integration
- **M-Pesa**: Daraja API for mobile payments
- **Transaction Management**: Custom reconciliation system

## System Architecture

### Backend Services (Django)
1. **Core SMS Processing Engine**
   - SMS gateway integration
   - Message queuing and delivery management
   - Delivery status tracking

2. **Contact Management System**
   - Phonebook operations
   - Contact segmentation and grouping
   - Bulk import/export

3. **Authentication Service**
   - User management
   - JWT token issuance and validation
   - Role and permission management

4. **Analytics & Reporting**
   - Message delivery statistics
   - Campaign performance metrics
   - Usage reporting

### Additional Backend Services (Node.js - *Future Implementation*)
1. **Payment & Subscription System**
   - M-Pesa integration
   - Subscription management and billing
   - Token tracking

2. **Webhook & API Gateway**
   - Client webhook configuration
   - API gateway for third-party integrations
   - Real-time event handling

3. **Real-time Chat Interface Backend**
   - WebSocket server for two-way messaging
   - Message history and threading
   - Notification system

### Frontend Components
1. **Dashboard**
   - Overview metrics
   - Quick access to key features

2. **Campaign Management**
   - Campaign creation and scheduling
   - Template management
   - Message personalization

3. **Contact Management**
   - Phonebook interface
   - Contact import/export
   - Group management

4. **Analytics Dashboard**
   - Delivery rates visualization
   - Campaign performance metrics
   - Usage statistics

5. **Account Management**
   - Subscription details
   - Billing history
   - Token purchase interface

## Setup Instructions

### Prerequisites
- Python 3.9+
- Node.js 16+
- PostgreSQL 13+
- Redis
- Virtual environment tool (virtualenv or conda)

### Backend Setup (Django)

1. Clone the repository
   ```bash
   git clone https://github.com/godigitalafrica/sms-platform.git
   cd sms-platform
   ```

2. Set up virtual environment
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables
   ```bash
   cp .env.example .env
   # Edit .env file with your database, SMS gateway credentials, and other settings
   ```

5. Run migrations
   ```bash
   python manage.py migrate
   ```

6. Create a superuser
   ```bash
   python manage.py createsuperuser
   ```

7. Run the development server
   ```bash
   python manage.py runserver
   ```

### Frontend Setup (React)

1. Navigate to the frontend directory
   ```bash
   cd frontend
   ```

2. Install dependencies
   ```bash
   npm install
   ```

3. Configure environment variables
   ```bash
   cp .env.example .env
   # Edit .env file with your API URLs and other frontend settings
   ```

4. Run the development server
   ```bash
   npm start
   ```

## Project Structure

```
go-digital-africa-sms/
├── backend/                  # Django project root
│   ├── config/               # Project settings
│   ├── api/                  # REST API endpoints
│   ├── accounts/             # User authentication and management
│   ├── messaging/            # Core SMS functionality
│   ├── contacts/             # Contact management
│   ├── subscriptions/        # Subscription and billing
│   ├── analytics/            # Reporting and metrics
│   ├── integrations/         # Third-party integrations
│   ├── manage.py             # Django management script
│   └── requirements.txt      # Python dependencies
│
├── frontend/                 # React application
│   ├── public/               # Static assets
│   ├── src/
│   │   ├── components/       # Reusable UI components
│   │   ├── pages/            # Page components
│   │   ├── context/          # React context providers
│   │   ├── hooks/            # Custom React hooks
│   │   ├── services/         # API service functions
│   │   ├── utils/            # Helper functions
│   │   ├── App.js            # Main application component
│   │   └── index.js          # Entry point
│   ├── package.json          # Node.js dependencies
│   └── tailwind.config.js    # Tailwind CSS configuration
│
├── docs/                     # Documentation
└── README.md                 # Project overview
```

## API Documentation

The API documentation is available at `/api/docs/` when running the development server. This documentation is generated using Swagger/OpenAPI and provides detailed information about available endpoints, request parameters, and response formats.

## Features

### Core Features
- User authentication and account management
- Contact management with grouping and segmentation
- Message templates and personalization
- Campaign scheduling and management
- Delivery tracking and reporting
- Two-way messaging capabilities

### Subscription Tiers
1. **Basic** (Small businesses, startups)
   - Limited monthly SMS allocation
   - Basic templates and scheduling
   - Standard delivery reports

2. **Professional** (Mid-sized businesses)
   - Larger SMS allocation
   - Advanced scheduling and targeting
   - Customized templates
   - Basic API access

3. **Enterprise** (Hotels, hospitals, large organizations)
   - Unlimited or very high SMS allocation
   - Full API access with webhooks
   - Priority sending
   - Dedicated account manager
   - White-labeling options

### Token-Based System
- Tokens purchased in bundles (e.g., 1,000, 5,000, 10,000)
- Token pricing tiers (larger bundles = lower per-token cost)
- Auto-renewal options
- Token expiry policies

### Value-Added Features
- Message personalization
- Short code rentals
- SMS surveys and polls
- Advanced analytics and reporting
- Custom integration services
- API access for third-party systems

## Development Guidelines

### Coding Standards
- **Python**: Follow PEP 8 style guide
- **JavaScript**: Use ESLint with Airbnb configuration
- **React**: Follow component-based architecture with functional components and hooks

### Git Workflow
1. Create feature branches from `develop` branch
2. Use descriptive branch names: `feature/feature-name`, `bugfix/issue-description`
3. Submit pull requests for code review before merging
4. Squash commits before merging to main branches

### Testing
- Backend: Django test framework with pytest
- Frontend: Jest and React Testing Library
- Run tests before submitting pull requests
- Maintain minimum 80% code coverage

## Deployment

### Production Environment Requirements
- Containerized deployment with Docker and Docker Compose
- NGINX as reverse proxy and static file server
- Gunicorn as WSGI application server
- SSL/TLS certification (Let's Encrypt recommended)
- Database backups and failover strategy

### Deployment Process
1. Build production-ready frontend
   ```bash
   cd frontend
   npm run build
   ```

2. Collect static files
   ```bash
   cd backend
   python manage.py collectstatic
   ```

3. Deploy using Docker Compose
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

## License
This project is proprietary and confidential. Unauthorized copying, distribution, or use is strictly prohibited.

## Contact
For any questions or support, please contact:
- Email: support@godigitalafrica.com
- Website: https://godigitalafrica.com
