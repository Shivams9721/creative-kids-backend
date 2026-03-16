# Creative Kids - Product Overview

## Project Purpose
Creative Kids is a full-stack e-commerce platform for selling children's clothing (baby and kids apparel) in India. It provides a complete online shopping experience with storefront, cart, checkout, user accounts, and an admin dashboard.

## Key Features & Capabilities

### Storefront
- Product catalog with category/subcategory browsing (Baby, Kids)
- Size and color filtering
- Product detail pages with image galleries
- Smart search functionality
- Featured products and new arrivals on homepage
- Homepage sections with configurable card slots

### Shopping Experience
- Persistent cart (via React Context)
- Cart drawer with real-time updates
- Checkout with address collection
- Order placement with automatic stock deduction (transactional)
- Order success confirmation page

### User Accounts
- Registration and login with JWT authentication
- User profile management (name, phone)
- Order history per user
- Wishlist (add/remove/toggle, verified buyer check)
- Verified-buyer-only product reviews with star ratings

### Admin Dashboard
- Secure admin login (separate JWT role)
- Dashboard stats: revenue, active orders, product count, today's orders, low stock alerts
- Product management: add, edit, soft-delete products
- Image upload directly to AWS S3 (via backend proxy)
- Order management: view all orders, update status, add courier name and AWB tracking number
- Inventory search and management
- Form draft persistence via localStorage

## Target Users
- **Shoppers**: Parents buying clothing for babies (0–3M to 24M) and kids (1Y–18Y)
- **Admin**: Store owner/manager managing products, orders, and inventory
- **Domain**: creativekids.co.in (India market, INR pricing)
