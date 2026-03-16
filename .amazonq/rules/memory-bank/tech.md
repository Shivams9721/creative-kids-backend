# Creative Kids - Tech Stack

## Backend
| Layer | Technology |
|---|---|
| Runtime | Node.js |
| Framework | Express 5.x |
| Database | PostgreSQL (AWS RDS) via `pg` 8.x connection pool |
| Auth | `jsonwebtoken` 9.x + `bcrypt` 6.x |
| File Upload | `multer` 2.x (memory storage) → AWS S3 |
| AWS SDK | `@aws-sdk/client-s3` v3 |
| Config | `dotenv` |
| Dev Server | `nodemon` |

### Backend Environment Variables (.env)
```
DATABASE_URL=
JWT_SECRET=
AWS_REGION=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_S3_BUCKET_NAME=
PORT=5000
```

### Backend Dev Commands
```bash
npm run dev     # nodemon index.js (hot reload)
npm start       # node index.js (production)
```

### Database Connection (db.js)
- Pool config: max 20 connections, 30s idle timeout, 5s connection timeout
- SSL enabled with `rejectUnauthorized: false` for AWS RDS
- Strips `?sslmode=require` from connection string before use

---

## Frontend
| Layer | Technology |
|---|---|
| Framework | Next.js 16.1.6 (App Router) |
| React | 19.2.3 |
| Language | JSX (pages/components) + TSX (layout, config) |
| Styling | Tailwind CSS 3.4.x |
| Animations | Framer Motion 12.x |
| Icons | Lucide React 0.575.x |
| Font | Inter (Google Fonts via `next/font`) |
| Linting | ESLint 10.x with `eslint-config-next` |

### Frontend Dev Commands
```bash
npm run dev     # next dev (Turbopack)
npm run build   # next build
npm start       # next start
npm run lint    # eslint
```

### Tailwind Config
- Content paths: `./app/**/*.{js,ts,jsx,tsx,mdx}`, `./components/**/*.{js,ts,jsx,tsx,mdx}`
- No custom theme extensions (uses Tailwind defaults)

### Path Aliases
- `@/` maps to project root (configured in tsconfig.json)
- Usage: `@/components/Navbar`, `@/context/CartContext`

---

## Infrastructure & Deployment
| Service | Usage |
|---|---|
| AWS App Runner | Backend hosting (`vbaumdstnz.ap-south-1.awsapprunner.com`) |
| AWS RDS | PostgreSQL database |
| AWS S3 | Product image storage |
| AWS Amplify | Frontend hosting (`main.d1ucppcuwyaa0p.amplifyapp.com`) |
| GoDaddy | Custom domain (`creativekids.co.in`) |

## CORS Allowed Origins
- `http://localhost:3000`
- `https://main.d1ucppcuwyaa0p.amplifyapp.com`
- `https://creativekids.co.in` / `https://www.creativekids.co.in`
- `https://creativekids.com` / `https://www.creativekids.com`
