# Creative Kids - Project Structure

## Monorepo Layout
Two separate workspaces side by side:
- `creative-kids-backend/` — Node.js/Express REST API
- `creative-kids-frontend/` — Next.js 15 storefront + admin

---

## Backend Structure
```
creative-kids-backend/
├── index.js        # All routes and Express app (single-file API)
├── db.js           # PostgreSQL connection pool (pg + SSL)
├── .env            # DATABASE_URL, JWT_SECRET, AWS credentials
└── package.json
```

### Backend Route Groups (all in index.js)
| Section | Routes |
|---|---|
| Products | `GET/POST /api/products`, `GET/PUT/DELETE /api/products/:id` |
| Admin Products | `GET /api/admin/products` (includes soft-deleted) |
| Orders | `POST /api/orders` (transactional), `GET /api/orders/user/:email` |
| Admin Orders | `GET /api/admin/orders`, `PUT /api/admin/orders/:id/status` |
| Auth | `POST /api/auth/register`, `POST /api/auth/login` |
| Admin Auth | `POST /api/admin/login` |
| User Profile | `GET /api/user/orders`, `PUT /api/user/profile` |
| Wishlist | `GET /api/wishlist`, `POST /api/wishlist/toggle`, `GET /api/wishlist/check/:productId` |
| Reviews | `GET /api/reviews/:productId`, `POST /api/reviews`, `GET /api/reviews/check/:productId` |
| Image Upload | `POST /api/upload`, `DELETE /api/upload` (S3 proxy) |
| Analytics | `GET /api/admin/analytics/revenue`, `/top-products`, `/order-funnel` |
| Stats | `GET /api/admin/stats/full` |

---

## Frontend Structure
```
creative-kids-frontend/
├── app/                        # Next.js App Router pages
│   ├── page.jsx                # Homepage
│   ├── layout.tsx              # Root layout (Navbar, Footer, CartProvider)
│   ├── globals.css
│   ├── shop/[[...slug]]/       # Catch-all shop page (category/subcategory/item filtering)
│   ├── product/[id]/           # Product detail page
│   ├── checkout/               # Checkout page
│   ├── success/                # Order confirmation
│   ├── login/                  # User login/register
│   ├── profile/                # User profile + order history + wishlist
│   ├── admin/page.jsx          # Admin dashboard (single-page, tab-based)
│   ├── admin/login/            # Admin login
│   ├── contact/
│   ├── privacy/
│   ├── refund-policy/
│   ├── shipping-policy/
│   └── terms/
├── components/
│   ├── Navbar.jsx              # Fixed header, announcement bar, mega menu, mobile drawer
│   ├── Footer.jsx
│   ├── CartDrawer.jsx          # Slide-out cart panel
│   ├── ProductGrid.jsx         # Reusable product listing grid
│   └── SmartSearch.jsx         # Full-screen search overlay
├── context/
│   └── CartContext.jsx         # Global cart state (React Context)
├── public/images/              # Static assets, logo
├── next.config.ts
├── tailwind.config.js
└── tsconfig.json
```

---

## Key Architectural Patterns

### Authentication Flow
- Users: JWT stored in `localStorage` as `"token"`, expires 10h
- Admin: JWT stored as `"adminToken"`, role claim `"admin"`, expires 12h
- Backend middleware: `authenticateToken` (users), `authenticateAdmin` (admin role check)

### Data Flow
- Frontend fetches directly from AWS App Runner backend URL
- No API abstraction layer — raw `fetch()` calls in each page/component
- Backend base URL: `https://vbaumdstnz.ap-south-1.awsapprunner.com`

### State Management
- Cart: React Context (`CartContext`) — in-memory only, not persisted
- Admin form drafts: `localStorage` (`adminFormDraft`, `adminActiveTab`, `adminEditingId`)
- Auth state: `localStorage` tokens checked on mount / pathname change

### Database
- PostgreSQL on AWS RDS via `pg` connection pool
- JSON fields stored as stringified JSON: `image_urls`, `sizes`, `colors`, `variants`, `items`, `shipping_address`
- Soft deletes on products (`is_active = false`)
- Order numbers formatted as `Creativekids-O-000001`

### Image Storage
- Images uploaded via backend proxy to AWS S3
- S3 key pattern: `products/{timestamp}-{random}.{ext}`
- Public URL pattern: `https://{bucket}.s3.{region}.amazonaws.com/products/...`

### Category Taxonomy
```
Baby
  ├── Baby Boy: Onesies & Rompers, T-Shirts & Sweatshirts, Shirts, Bottomwear, Clothing Sets
  └── Baby Girl: Onesies & Rompers, Tops & Tees, Dresses, Bottomwear, Clothing Sets
Kids
  ├── Boys Clothing: T-Shirts, Shirts, Jeans, Trousers & Joggers, Shorts, Co-ord Sets, Sweatshirts
  └── Girls Clothing: Tops & Tees, Dresses, Co-ords & Jumpsuits, Jeans Joggers & Trousers, Shorts Skirts & Skorts
```
Shop URL slug pattern: `/shop/{main-category-slug}/{item-type-slug}`
