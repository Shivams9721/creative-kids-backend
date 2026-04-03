# Creative Kids — Backend

Express.js API for Creative Kids. PostgreSQL on AWS RDS, images on S3, emails via SES, payments via Razorpay.

## Setup

```bash
npm install
```

Create `.env`:

```
DATABASE_URL=postgresql://...
JWT_SECRET=...
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=ap-south-1
AWS_S3_BUCKET_NAME=...
SMTP_HOST=email-smtp.ap-south-1.amazonaws.com
SMTP_PORT=587
SMTP_USER=...
SMTP_PASS=...
SES_FROM_EMAIL=noreply@yourdomain.com
RAZORPAY_KEY_ID=...
RAZORPAY_KEY_SECRET=...
CSRF_SECRET=...
```

Run migrations (first time only):

```bash
node migrate.js
```

Start server:

```bash
npm start        # production
npm run dev      # development (nodemon)
```

## API Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/products | — | All active products |
| GET | /api/products/:id | — | Single product |
| POST | /api/auth/register | — | Register |
| POST | /api/auth/login | — | Login |
| POST | /api/auth/send-otp | — | Send OTP |
| POST | /api/auth/verify-otp | — | Verify OTP |
| POST | /api/orders | User | Place order |
| GET | /api/user/orders | User | My orders |
| GET | /api/user/address | User | My addresses |
| POST | /api/user/address | User | Add address |
| GET | /api/wishlist | User | My wishlist |
| POST | /api/wishlist/toggle | User | Toggle wishlist |
| POST | /api/payment/create-order | User | Create Razorpay order |
| POST | /api/payment/verify | User | Verify payment |
| GET | /api/admin/orders | Admin | All orders |
| PUT | /api/admin/orders/:id/status | Admin | Update order status |
| GET | /api/admin/products | Admin | All products |
| POST | /api/products | Admin | Create product |
| PUT | /api/products/:id | Admin | Update product |
| PATCH | /api/products/:id/stock | Admin | Update stock only |
| GET | /api/admin/stats/full | Admin | Dashboard stats |
| GET | /api/admin/analytics/revenue | Admin | Revenue chart |
| GET | /api/admin/coupons | Admin | List coupons |
| POST | /api/admin/coupons | Admin | Create coupon |
