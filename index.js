const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { doubleCsrf } = require('csrf-csrf');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const pool = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const nodemailer = require('nodemailer');
const Razorpay = require('razorpay');
require('dotenv').config();

const app = express();

// Security headers via helmet (all protections enabled)
app.use(helmet());

// CSRF Protection Setup
let generateCsrfToken, validateRequest, invalidCsrfTokenError;
try {
  const csrf = doubleCsrf({
    getSecret: () => process.env.CSRF_SECRET || 'fallback-secret',
    cookieName: "__host-psifi.x-csrf-token",
    cookieOptions: {
      sameSite: "lax",
      path: "/",
      secure: process.env.NODE_ENV === 'production',
    },
  });
  generateCsrfToken = csrf.generateCsrfToken;
  validateRequest = csrf.validateRequest;
  invalidCsrfTokenError = csrf.invalidCsrfTokenError;
  console.log('✓ CSRF initialized');
} catch(e) {
  console.warn('CSRF setup failed, using no-op:', e.message);
  generateCsrfToken = (req, res) => 'none';
  validateRequest = (req, res, next) => next();
  invalidCsrfTokenError = null;
}

// Middleware (Updated CORS for AWS Amplify and Custom Domains)
app.use(cors({
    origin: [
      'http://localhost:3000', 
      'https://main.d1ucppcuwyaa0p.amplifyapp.com',
      'https://creativekids.com',
      'https://www.creativekids.com',
      'https://creativekids.co.in',
      'https://www.creativekids.co.in'
    ], 
    credentials: true
}));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// Generate and send CSRF token to the frontend
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = generateCsrfToken(req, res);
  res.json({ csrfToken });
});

// ==========================================
// EMAIL (AWS SES via SMTP)
// ==========================================
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

const sendOtpEmail = async (toEmail, otp, purpose) => {
  const isReset = purpose === 'reset';
  await mailer.sendMail({
    from: `"Creative Kids" <${process.env.SES_FROM_EMAIL}>`,
    to: toEmail,
    subject: isReset ? 'Reset Your Password — Creative Kids' : 'Your Login OTP — Creative Kids',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#fff;border:1px solid #eee;border-radius:12px">
        <h2 style="font-size:20px;font-weight:300;color:#000;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px">Creative Kids</h2>
        <p style="font-size:12px;color:#999;text-transform:uppercase;letter-spacing:2px;margin-bottom:32px">Premium Children's Clothing</p>
        <p style="font-size:14px;color:#333;margin-bottom:24px">${isReset ? 'Use this OTP to reset your password.' : 'Use this OTP to sign in to your account.'} It expires in <strong>10 minutes</strong>.</p>
        <div style="background:#f6f5f3;border-radius:8px;padding:24px;text-align:center;margin-bottom:24px">
          <span style="font-size:36px;font-weight:700;letter-spacing:12px;color:#000">${otp}</span>
        </div>
        <p style="font-size:12px;color:#999">If you didn't request this, please ignore this email. Do not share this OTP with anyone.</p>
      </div>
    `
  });
};

// JWT Secret Key (Used for keeping users logged in safely)
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET environment variable is not set');

// ==========================================
// RAZORPAY SETUP
// ==========================================
let razorpay = null;

if (process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET) {
  razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
  });
  console.log('✓ Razorpay initialized');
} else {
  console.warn('⚠️  Razorpay credentials not configured. Online payments will not work.');
}


// ==========================================
// GLOBAL SECURITY MIDDLEWARE
// ==========================================

// Middleware to verify the user's digital wristband (JWT)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: "Access Denied. No token provided." });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid or expired token." });
    req.user = decoded.user;
    next();
  });
};

// Middleware to verify admin token
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: "Access Denied. No token provided." });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err || decoded.role !== 'admin') return res.status(403).json({ message: "Invalid or expired admin token." });
    req.admin = decoded;
    next();
  });
};


// ==========================================
// AWS S3 IMAGE UPLOAD SETUP
// ==========================================

// Helper: Validate product data
const validateProductData = (data, isDraft) => {
  if (isDraft) return null; // Skip validation for drafts
  
  if (!data.title || !data.title.trim()) return 'Product title is required';
  if (!data.price || parseFloat(data.price) <= 0) return 'Valid selling price is required';
  if (!data.mrp || parseFloat(data.mrp) <= 0) return 'Valid MRP is required';
  if (parseFloat(data.price) > parseFloat(data.mrp)) return 'Selling price cannot exceed MRP';
  if (!data.main_category) return 'Main category is required';
  if (!data.sub_category) return 'Sub category is required';
  if (!data.item_type) return 'Item type is required';
  if (!data.image_urls || data.image_urls.length === 0) return 'At least one image is required';
  if (!data.sizes || data.sizes.length === 0) return 'At least one size is required';
  if (!data.colors || data.colors.length === 0) return 'At least one color is required';
  
  // Validate image URLs are from S3
  const s3Pattern = new RegExp(`^https://${process.env.AWS_S3_BUCKET_NAME}\\.s3\\.${process.env.AWS_REGION}\\.amazonaws\\.com/products/`);
  for (const url of data.image_urls) {
    if (!s3Pattern.test(url)) {
      return 'Invalid image URL detected. Images must be uploaded through the system.';
    }
  }
  
  // Validate homepage card slot
  if (data.homepage_card_slot !== null && data.homepage_card_slot !== undefined) {
    const slot = parseInt(data.homepage_card_slot);
    if (isNaN(slot) || slot < 1 || slot > 8) {
      return 'Homepage card slot must be between 1 and 8';
    }
  }
  
  return null;
};

// 1. Configure AWS S3 Client
const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

// 2. Configure Multer (Temporarily holds the image in RAM)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });

// 3. Delete a single image from S3
app.delete('/api/upload', authenticateAdmin, validateRequest, async (req, res) => {
  try {
    const { imageUrl } = req.body;
    if (!imageUrl) return res.status(400).json({ error: "No imageUrl provided." });

    // Extract and validate the S3 key — must start with 'products/'
    const parts = imageUrl.split('.amazonaws.com/');
    if (parts.length < 2) return res.status(400).json({ error: 'Invalid image URL.' });
    const key = parts[1];
    if (!key.startsWith('products/')) return res.status(400).json({ error: 'Invalid image path.' });
    await s3.send(new DeleteObjectCommand({ Bucket: process.env.AWS_S3_BUCKET_NAME, Key: key }));

    res.json({ success: true });
  } catch (error) {
    console.error("S3 Delete Error:", error);
    res.status(500).json({ error: "Failed to delete image from cloud storage." });
  }
});

// 4. The Upload API Route
app.post('/api/upload', authenticateAdmin, validateRequest, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No image file provided." });
    }

    // Create a unique file name so images don't overwrite each other
    const fileExtension = req.file.originalname.split('.').pop();
    const fileName = `products/${Date.now()}-${Math.round(Math.random() * 1E9)}.${fileExtension}`;

    // Command to send the file to AWS S3
    const command = new PutObjectCommand({
      Bucket: process.env.AWS_S3_BUCKET_NAME,
      Key: fileName,
      Body: req.file.buffer,
      ContentType: req.file.mimetype,
    });

    await s3.send(command);

    // Create the public URL to save in the database
    const imageUrl = `https://${process.env.AWS_S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${fileName}`;

    res.json({ success: true, imageUrl: imageUrl });
  } catch (error) {
    console.error("AWS S3 Upload Error:", error);
    res.status(500).json({ error: "Failed to upload image to cloud storage." });
  }
});


// ==========================================
// 1. PRODUCT ROUTES
// ==========================================

// GET: All Products (only active, published ones for storefront)
app.get('/api/products', async (req, res) => {
  try {
    const { sub_category, main_category, new_arrival } = req.query;
    let query = `SELECT * FROM products WHERE is_active = true`;
    const values = [];
    if (main_category) {
      values.push(main_category);
      query += ` AND main_category = $${values.length}`;
    }
    if (sub_category) {
      values.push(sub_category);
      query += ` AND sub_category = $${values.length}`;
    }
    if (new_arrival === 'true') {
      query += ` AND is_new_arrival = true`;
    }
    query += ` ORDER BY id DESC`;
    if (sub_category || main_category || new_arrival) query += ` LIMIT 120`;
    query += `;`;
    const allProducts = await pool.query(query, values);
    res.json(allProducts.rows);
  } catch (err) {
    console.error("Products GET Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// GET: Single Product by ID
app.get('/api/products/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) return res.status(400).json({ message: "Invalid product ID" });
    if (!id) return res.status(404).json({ message: "Product not found" });
    const query = `SELECT * FROM products WHERE id = $1;`;
    const product = await pool.query(query, [id]);

    if (product.rows.length === 0) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.json(product.rows[0]);
  } catch (err) {
    console.error("Single Product GET Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// POST: Add new product
app.post("/api/products", authenticateAdmin, validateRequest, async (req, res) => {
  try {
    const {
      title, description, price, mrp, image_urls, sizes, colors, is_featured, is_new_arrival, homepage_section, homepage_card_slot,
      sku, hsn_code, fabric, pattern, neck_type, belt_included,
      closure_type, length_type,
      manufacturer_details, care_instructions, origin_country,
      main_category, sub_category, item_type, variants, extra_categories, color_images
    } = req.body;

    const { is_draft } = req.body;

    // Validate product data
    const validationError = validateProductData(req.body, is_draft);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const query = `
      INSERT INTO products (
        title, description, price, mrp, image_urls, sizes, colors, is_featured, is_new_arrival, homepage_section, homepage_card_slot,
        sku, hsn_code, fabric, pattern, neck_type, belt_included, closure_type, length_type,
        manufacturer_details, care_instructions, origin_country,
        main_category, sub_category, item_type, category, variants, extra_categories, color_images, is_draft
      ) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30) 
      RETURNING *;
    `;

    const values = [
      title, description, price, mrp, 
      JSON.stringify(image_urls), 
      JSON.stringify(sizes), 
      JSON.stringify(colors), 
      is_featured, is_new_arrival, homepage_section, homepage_card_slot,
      sku, hsn_code, fabric, pattern, neck_type, belt_included,
      closure_type || null, length_type || null,
      manufacturer_details, care_instructions, origin_country,
      main_category, sub_category, item_type, sub_category,
      JSON.stringify(variants),
      JSON.stringify(extra_categories || []),
      JSON.stringify(color_images || {}),
      is_draft || false
    ];

    const newProduct = await pool.query(query, values);
    res.json(newProduct.rows[0]);
  } catch (err) {
    console.error("Product POST Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// PUT: Restore a soft-deleted product
app.put("/api/products/:id/restore", authenticateAdmin, validateRequest, async (req, res) => {
  try {
    await pool.query("UPDATE products SET is_active = true WHERE id = $1", [req.params.id]);
    res.json({ message: "Product restored" });
  } catch (err) {
    res.status(500).json({ error: "Server Error" });
  }
});

// PUT: Update an existing product
app.put("/api/products/:id", authenticateAdmin, validateRequest, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      title, description, price, mrp, image_urls, sizes, colors, is_featured, is_new_arrival, homepage_section, homepage_card_slot,
      sku, hsn_code, fabric, pattern, neck_type, belt_included,
      closure_type, length_type,
      manufacturer_details, care_instructions, origin_country,
      main_category, sub_category, item_type, variants, extra_categories, color_images
    } = req.body;

    const { is_draft } = req.body;

    // Validate product data
    const validationError = validateProductData(req.body, is_draft);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const query = `
      UPDATE products SET 
        title = $1, description = $2, price = $3, mrp = $4, image_urls = $5, sizes = $6, colors = $7, 
        is_featured = $8, is_new_arrival = $9, homepage_section = $10, homepage_card_slot = $11,
        sku = $12, hsn_code = $13, fabric = $14, pattern = $15, neck_type = $16, belt_included = $17,
        closure_type = $18, length_type = $19,
        manufacturer_details = $20, care_instructions = $21, origin_country = $22,
        main_category = $23, sub_category = $24, item_type = $25, category = $26, variants = $27,
        extra_categories = $28, color_images = $29, is_draft = $30
      WHERE id = $31 RETURNING *;
    `;

    const values = [
      title, description, price, mrp, 
      JSON.stringify(image_urls), 
      JSON.stringify(sizes), 
      JSON.stringify(colors), 
      is_featured, is_new_arrival, homepage_section, homepage_card_slot,
      sku, hsn_code, fabric, pattern, neck_type, belt_included,
      closure_type || null, length_type || null,
      manufacturer_details, care_instructions, origin_country,
      main_category, sub_category, item_type, sub_category,
      JSON.stringify(variants),
      JSON.stringify(extra_categories || []),
      JSON.stringify(color_images || {}),
      is_draft || false,
      id
    ];

    const updatedProduct = await pool.query(query, values);
    res.json(updatedProduct.rows[0]);
  } catch (err) {
    console.error("Product PUT Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// DELETE: Soft delete — requires explicit { confirm: "DELETE" } in body as a safety guard
app.delete("/api/products/:id", authenticateAdmin, validateRequest, async (req, res) => {
  try {
    if (req.body?.confirm !== "DELETE") {
      return res.status(400).json({ error: "Missing confirmation. Send { confirm: 'DELETE' } to proceed." });
    }
    const { id } = req.params;
    await pool.query("UPDATE products SET is_active = false WHERE id = $1", [id]);
    res.json({ message: "Product removed from storefront" });
  } catch (err) {
    console.error("Delete Product Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});


// GET: Homepage data (new arrivals, bestsellers, featured)
app.get('/api/homepage', async (req, res) => {
  try {
    const newArrivals = await pool.query(
      `SELECT * FROM products WHERE is_active = true AND is_new_arrival = true ORDER BY created_at DESC LIMIT 4`
    );
    const bestsellers = await pool.query(
      `SELECT * FROM products WHERE is_active = true ORDER BY id DESC LIMIT 4`
    );
    const featured = await pool.query(
      `SELECT * FROM products WHERE is_active = true AND is_featured = true ORDER BY id DESC LIMIT 8`
    );
    res.json({
      newArrivals: newArrivals.rows,
      bestsellers: bestsellers.rows,
      featured: featured.rows
    });
  } catch (err) {
    console.error('Homepage GET Error:', err.message);
    res.status(500).json({ error: 'Server Error' });
  }
});

// ==========================================
// 2. ADMIN DASHBOARD ROUTES
// ==========================================

// GET: All products for Admin (including soft-deleted)
app.get('/api/admin/products', authenticateAdmin, async (req, res) => {
  try {
    const allProducts = await pool.query(`SELECT * FROM products ORDER BY id DESC;`);
    res.json(allProducts.rows);
  } catch (err) {
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// GET: Live stats for the Admin Overview Panel
app.get("/api/admin/stats", authenticateAdmin, async (req, res) => {
  try {
    const productCount = await pool.query("SELECT COUNT(*) FROM products");
    const orderCount = await pool.query("SELECT COUNT(*) FROM orders WHERE status != 'Delivered'");
    const revenue = await pool.query("SELECT SUM(total_amount) FROM orders");

    res.json({
      totalProducts: parseInt(productCount.rows[0].count) || 0,
      activeOrders: parseInt(orderCount.rows[0].count) || 0,
      revenue: parseFloat(revenue.rows[0].sum) || 0
    });
  } catch (err) {
    console.error("Admin Stats Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});


// ==========================================
// 3. ORDER ROUTES (ADVANCED)
// ==========================================

// POST: Create a new order + deduct stock
app.post("/api/orders", authenticateToken, validateRequest, async (req, res) => {
  const client = await pool.connect();
  try {
    const { cartItems, address, paymentMethod, couponCode, discountAmount } = req.body;
    // Always derive email from the verified JWT — never trust client-supplied email
    const userRes = await client.query('SELECT email FROM users WHERE id = $1', [req.user.id]);
    if (userRes.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    const userEmail = userRes.rows[0].email;

    await client.query('BEGIN');

    // 1. Re-fetch prices from DB and deduct stock — never trust client-supplied prices
    let serverTotal = 0;
    const enrichedItems = [];
    for (const item of cartItems) {
      const productRes = await client.query("SELECT price, title, variants FROM products WHERE id = $1 AND is_active = true", [item.id]);
      if (productRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: `Product ${item.id} is no longer available.` });
      }
      const product = productRes.rows[0];
      const qty = parseInt(item.quantity) || 1;
      serverTotal += parseFloat(product.price) * qty;

      let variants = [];
      try { variants = typeof product.variants === 'string' ? JSON.parse(product.variants) : (product.variants || []); } catch(e) {}

      const itemColor = item.selectedColor || item.color || 'Default';
      const itemSize = item.selectedSize || item.size || 'Default';
      const updated = variants.map(v => {
        const colorMatch = v.color === itemColor || (itemColor === 'Default' && v.color === 'Default');
        const sizeMatch = v.size === itemSize || (itemSize === 'Default' && v.size === 'Default');
        if (colorMatch && sizeMatch) {
          return { ...v, stock: Math.max(0, v.stock - qty) };
        }
        return v;
      });
      await client.query("UPDATE products SET variants = $1 WHERE id = $2", [JSON.stringify(updated), item.id]);

      enrichedItems.push({ ...item, price: parseFloat(product.price), title: product.title });
    }

    const discountAmt = parseFloat(discountAmount) || 0;
    const finalAmount = Math.max(0, serverTotal - discountAmt);

    // 2. Insert the order
    const result = await client.query(
      `INSERT INTO orders (customer_name, phone, total_amount, items_count, status, shipping_address, items, payment_method, user_email, coupon_code, discount_amount)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id;`,
      [address.fullName, address.phone, finalAmount, enrichedItems.length, 'Processing',
       JSON.stringify(address), JSON.stringify(enrichedItems), paymentMethod, userEmail,
       couponCode || null, discountAmt]
    );
    const newId = result.rows[0].id;
    const orderNumber = `Creativekids-O-${String(newId).padStart(6, '0')}`;
    await client.query(`UPDATE orders SET order_number = $1 WHERE id = $2`, [orderNumber, newId]);
    if (couponCode) {
      await client.query('UPDATE coupons SET uses = uses + 1 WHERE UPPER(code) = UPPER($1)', [couponCode]);
    }

    await client.query('COMMIT');
    res.json({ success: true, order_number: orderNumber });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Create Order Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  } finally {
    client.release();
  }
});

// Fetch orders specifically for the logged-in customer's profile
app.get("/api/orders/user/:email", authenticateToken, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT email FROM users WHERE id = $1', [req.user.id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const result = await pool.query("SELECT * FROM orders WHERE user_email = $1 ORDER BY id DESC", [userRes.rows[0].email]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ==========================================
// 4. AUTHENTICATION & USER ROUTES
// ==========================================

// Register a New User
app.post("/api/auth/register", validateRequest, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const userExists = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ message: "User already exists with that email" });
    }

    const saltRound = 10;
    const salt = await bcrypt.genSalt(saltRound);
    const bcryptPassword = await bcrypt.hash(password, salt);

    const newUser = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name, email, bcryptPassword]
    );

    const token = jwt.sign({ user: { id: newUser.rows[0].id } }, JWT_SECRET, { expiresIn: "10h" });

    res.json({ token, user: newUser.rows[0] });
  } catch (err) {
    console.error("Register Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// Login an Existing User
app.post("/api/auth/login", validateRequest, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (user.rows.length === 0) {
      return res.status(401).json({ message: "Invalid Email or Password" });
    }

    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid Email or Password" });
    }

    const token = jwt.sign({ user: { id: user.rows[0].id } }, JWT_SECRET, { expiresIn: "10h" });

    res.json({ token, user: { id: user.rows[0].id, name: user.rows[0].name, email: user.rows[0].email } });
  } catch (err) {
    console.error("Login Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});


// ==========================================
// OTP ROUTES
// ==========================================

// POST: Send OTP (login or reset)
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { email, purpose } = req.body;
    if (!email || !purpose) return res.status(400).json({ error: 'Email and purpose are required.' });
    if (!['login', 'reset'].includes(purpose)) return res.status(400).json({ error: 'Invalid purpose.' });

    if (purpose === 'reset') {
      const userRes = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
      if (userRes.rows.length === 0) return res.json({ success: true }); // silent — don't reveal
    }

    // Rate limit: max 3 OTPs per 10 minutes
    const recentCount = await pool.query(
      `SELECT COUNT(*) FROM otps WHERE identifier = $1 AND created_at > NOW() - INTERVAL '10 minutes'`,
      [email]
    );
    if (parseInt(recentCount.rows[0].count) >= 3)
      return res.status(429).json({ error: 'Too many requests. Please wait 10 minutes.' });

    const otp = String(crypto.randomInt(100000, 1000000));
    const expires = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query('UPDATE otps SET used = true WHERE identifier = $1 AND purpose = $2 AND used = false', [email, purpose]);
    await pool.query('INSERT INTO otps (identifier, otp, purpose, expires_at) VALUES ($1, $2, $3, $4)', [email, otp, purpose, expires]);
    await sendOtpEmail(email, otp, purpose);

    res.json({ success: true });
  } catch (err) {
    console.error('Send OTP Error:', err.message);
    res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
  }
});

// POST: Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp, purpose } = req.body;
    if (!email || !otp || !purpose) return res.status(400).json({ error: 'All fields are required.' });

    const result = await pool.query(
      `SELECT * FROM otps WHERE identifier = $1 AND otp = $2 AND purpose = $3 AND used = false AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [email, otp, purpose]
    );
    if (result.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired OTP.' });

    await pool.query('UPDATE otps SET used = true WHERE id = $1', [result.rows[0].id]);

    if (purpose === 'login') {
      let userRes = await pool.query('SELECT id, name, email FROM users WHERE email = $1', [email]);
      if (userRes.rows.length === 0) {
        const name = email.split('@')[0];
        userRes = await pool.query(
          'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
          [name, email, await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 10)]
        );
      }
      const user = userRes.rows[0];
      const token = jwt.sign({ user: { id: user.id } }, JWT_SECRET, { expiresIn: '10h' });
      return res.json({ success: true, token, user });
    }

    if (purpose === 'reset') {
      const resetToken = crypto.randomBytes(32).toString('hex');
      const expires = new Date(Date.now() + 15 * 60 * 1000);
      const userRes = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
      if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found.' });
      await pool.query(
        `INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)
         ON CONFLICT (user_id) DO UPDATE SET token = $2, expires_at = $3`,
        [userRes.rows[0].id, resetToken, expires]
      );
      return res.json({ success: true, resetToken });
    }
  } catch (err) {
    console.error('Verify OTP Error:', err.message);
    res.status(500).json({ error: 'Server Error' });
  }
});

// POST: Forgot Password — generates a reset token
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const userRes = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    // Always return success to prevent email enumeration
    if (userRes.rows.length === 0) return res.json({ success: true });

    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 1000 * 60 * 60); // 1 hour
    await pool.query(
      `INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO UPDATE SET token = $2, expires_at = $3`,
      [userRes.rows[0].id, token, expires]
    );
    // In production wire this to AWS SES. Token is NOT returned in response.
    res.json({ success: true });
  } catch (err) {
    console.error("Forgot Password Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// POST: Reset Password — validates token and sets new password
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;
    const result = await pool.query(
      "SELECT user_id, expires_at FROM password_reset_tokens WHERE token = $1",
      [token]
    );
    if (result.rows.length === 0) return res.status(400).json({ error: "Invalid or expired reset link." });
    if (new Date() > new Date(result.rows[0].expires_at)) return res.status(400).json({ error: "Reset link has expired." });

    const hashed = await bcrypt.hash(password, 10);
    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashed, result.rows[0].user_id]);
    await pool.query("DELETE FROM password_reset_tokens WHERE token = $1", [token]);
    res.json({ success: true });
  } catch (err) {
    console.error("Reset Password Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});


// ==========================================
// 5. SECURE USER PROFILE ROUTES
// ==========================================

// GET: Fetch ONLY the logged-in user's orders
app.get('/api/user/orders', authenticateToken, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT email FROM users WHERE id = $1', [req.user.id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const userOrders = await pool.query(
      "SELECT * FROM orders WHERE user_email = $1 ORDER BY created_at DESC",
      [userRes.rows[0].email]
    );
    res.json(userOrders.rows);
  } catch (err) {
    console.error("User Orders GET Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});


// PUT: Update user profile (name, phone)
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, phone } = req.body;
    await pool.query('UPDATE users SET name = $1, phone = $2 WHERE id = $3', [name, phone, userId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ==========================================
// 6. WISHLIST ROUTES
// ==========================================

// Check if a specific product is in the user's wishlist
app.get('/api/wishlist/check/:productId', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { productId } = req.params;

    const check = await pool.query("SELECT * FROM wishlist WHERE user_id = $1 AND product_id = $2", [userId, productId]);
    res.json({ isWishlisted: check.rows.length > 0 });
  } catch (err) {
    console.error("Wishlist Check Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// Toggle Wishlist (Add if missing, Remove if already there)
app.post('/api/wishlist/toggle', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { productId } = req.body;

    const check = await pool.query("SELECT * FROM wishlist WHERE user_id = $1 AND product_id = $2", [userId, productId]);

    if (check.rows.length > 0) {
      await pool.query("DELETE FROM wishlist WHERE user_id = $1 AND product_id = $2", [userId, productId]);
      res.json({ message: "Removed from wishlist", isWishlisted: false });
    } else {
      await pool.query("INSERT INTO wishlist (user_id, product_id) VALUES ($1, $2)", [userId, productId]);
      res.json({ message: "Added to wishlist", isWishlisted: true });
    }
  } catch (err) {
    console.error("Wishlist Toggle Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// Get ALL wishlist items for the logged-in user's profile
app.get('/api/wishlist', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const query = `
      SELECT p.id, p.title, p.price, p.mrp, p.image_urls, p.category, w.created_at 
      FROM products p
      JOIN wishlist w ON p.id = w.product_id
      WHERE w.user_id = $1
      ORDER BY w.created_at DESC;
    `;
    const result = await pool.query(query, [userId]);
    res.json(result.rows);
  } catch (err) {
    console.error("Wishlist GET Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});


// ==========================================
// 7. SECURE ADMIN AUTHENTICATION
// ==========================================
app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const adminCheck = await pool.query(
      "SELECT * FROM users WHERE email = $1 AND role = 'admin'", [email]
    );
    if (adminCheck.rows.length === 0) {
      return res.status(401).json({ error: "Unauthorized", message: "Invalid Admin Credentials" });
    }

    const dbAdmin = adminCheck.rows[0];
    // Enforce bcrypt comparison for all passwords
    const isValid = await bcrypt.compare(password, dbAdmin.password);

    if (isValid) {
      const token = jwt.sign({ role: "admin", id: dbAdmin.id }, JWT_SECRET, { expiresIn: "12h" });
      res.json({ success: true, token });
    } else {
      res.status(401).json({ error: "Unauthorized", message: "Invalid Admin Credentials" });
    }
  } catch (err) {
    console.error("Admin Login Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});


// ==========================================
// 8. DEDICATED ADMIN ORDER ROUTES 
// ==========================================

// 1. Fetch all orders (specifically for the Admin Dashboard)
app.get("/api/admin/orders", authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM orders ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    console.error("Admin Fetch Orders Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// 2. Update order status + AWB tracking number
app.put("/api/admin/orders/:id/status", authenticateAdmin, async (req, res) => {
  try {
    const { status, courier_name, awb_number } = req.body;
    const result = await pool.query(
      "UPDATE orders SET status = $1, courier_name = $2, awb_number = $3 WHERE id = $4 RETURNING *",
      [status, courier_name || null, awb_number || null, req.params.id]
    );
    res.json({ success: true, order: result.rows[0] });
  } catch (err) {
    console.error("Admin Update Status Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});


// ==========================================
// 9. REVIEWS ROUTES (VERIFIED BUYERS ONLY)
// ==========================================

// GET: Check if logged-in user can review (verified buyer + not already reviewed)
app.get('/api/reviews/check/:productId', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { productId } = req.params;

    // Get user email
    const userRes = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) return res.json({ canReview: false });
    const email = userRes.rows[0].email;

    // Check if user has ordered this product
    const pidCheck = parseInt(productId, 10);
    if (!pidCheck) return res.json({ canReview: false });
    const orderRes = await pool.query(
      `SELECT id FROM orders WHERE user_email = $1 AND status = 'Delivered' AND items @> jsonb_build_array(jsonb_build_object('id', $2::integer))`,
      [email, pidCheck]
    );
    const hasBought = orderRes.rows.length > 0;

    // Check if already reviewed
    const reviewRes = await pool.query(
      'SELECT id FROM reviews WHERE user_id = $1 AND product_id = $2',
      [userId, pidCheck]
    );
    const alreadyReviewed = reviewRes.rows.length > 0;

    res.json({ canReview: hasBought && !alreadyReviewed, alreadyReviewed });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET: Fetch all reviews for a product
app.get('/api/reviews/:productId', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, user_name, rating, comment, created_at FROM reviews WHERE product_id = $1 ORDER BY created_at DESC',
      [req.params.productId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST: Submit a review (verified buyers only)
app.post('/api/reviews', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { productId, rating, comment } = req.body;

    // Get user info
    const userRes = await pool.query('SELECT name, email FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const { name, email } = userRes.rows[0];

    // Verify buyer — cast productId to int to prevent injection
    const pid = parseInt(productId, 10);
    if (!pid) return res.status(400).json({ error: 'Invalid product ID.' });
    const orderRes = await pool.query(
      `SELECT id FROM orders WHERE user_email = $1 AND status = 'Delivered' AND items @> jsonb_build_array(jsonb_build_object('id', $2::integer))`,
      [email, pid]
    );
    if (orderRes.rows.length === 0)
      return res.status(403).json({ error: 'Only verified buyers can review this product.' });

    // Prevent duplicate review
    const existing = await pool.query(
      'SELECT id FROM reviews WHERE user_id = $1 AND product_id = $2',
      [userId, pid]
    );
    if (existing.rows.length > 0)
      return res.status(400).json({ error: 'You have already reviewed this product.' });

    if (!Number.isInteger(parseInt(rating, 10)) || rating < 1 || rating > 5)
      return res.status(400).json({ error: 'Rating must be between 1 and 5.' });
    const result = await pool.query(
      'INSERT INTO reviews (product_id, user_id, user_name, rating, comment) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [pid, userId, name, parseInt(rating, 10), comment]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ==========================================
// 10. ADVANCED ANALYTICS ROUTES
// ==========================================

// GET: Revenue by day (last 30 days)
app.get('/api/admin/analytics/revenue', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT DATE(created_at) as date, SUM(total_amount) as revenue, COUNT(*) as orders
      FROM orders
      WHERE created_at >= NOW() - INTERVAL '30 days'
      GROUP BY DATE(created_at)
      ORDER BY date ASC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET: Top selling products
app.get('/api/admin/analytics/top-products', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.id, p.title, p.sku, p.price, p.image_urls,
        COUNT(DISTINCT o.id) as order_count,
        SUM(o.total_amount) as total_revenue
      FROM products p
      JOIN orders o ON o.items::jsonb @> jsonb_build_array(jsonb_build_object('id', p.id))
      WHERE o.status != 'Cancelled'
      GROUP BY p.id
      ORDER BY order_count DESC
      LIMIT 10
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET: Order status breakdown
app.get('/api/admin/analytics/order-funnel', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT status, COUNT(*) as count, SUM(total_amount) as value
      FROM orders
      GROUP BY status
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET: Full admin stats (enhanced)
app.get('/api/admin/stats/full', authenticateAdmin, async (req, res) => {
  try {
    const [revenue, orders, products, todayOrders, lowStock] = await Promise.all([
      pool.query("SELECT SUM(total_amount) as total, COUNT(*) as count FROM orders WHERE status != 'Cancelled'"),
      pool.query("SELECT COUNT(*) FROM orders WHERE status NOT IN ('Delivered','Cancelled')"),
      pool.query("SELECT COUNT(*) FROM products WHERE is_active = true"),
      pool.query("SELECT COUNT(*), SUM(total_amount) FROM orders WHERE DATE(created_at) = CURRENT_DATE"),
      pool.query(`SELECT COUNT(*) FROM products WHERE is_active = true AND (
        SELECT COALESCE(SUM((v->>'stock')::int), 0) FROM jsonb_array_elements(variants::jsonb) v
      ) < 10`)
    ]);
    res.json({
      totalRevenue: parseFloat(revenue.rows[0].total) || 0,
      totalOrders: parseInt(revenue.rows[0].count) || 0,
      activeOrders: parseInt(orders.rows[0].count) || 0,
      totalProducts: parseInt(products.rows[0].count) || 0,
      todayOrders: parseInt(todayOrders.rows[0].count) || 0,
      todayRevenue: parseFloat(todayOrders.rows[0].sum) || 0,
      lowStockProducts: parseInt(lowStock.rows[0].count) || 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET: Search orders
app.get('/api/admin/orders/search', authenticateAdmin, async (req, res) => {
  try {
    const { q } = req.query;
    const result = await pool.query(
      `SELECT * FROM orders WHERE order_number ILIKE $1 OR customer_name ILIKE $1 OR user_email ILIKE $1 OR phone ILIKE $1 ORDER BY id DESC LIMIT 20`,
      [`%${q}%`]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// POST: Cancel an order (user-initiated, only if Processing)
app.post('/api/orders/:id/cancel', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const userRes = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const email = userRes.rows[0].email;

    const orderRes = await pool.query(
      'SELECT * FROM orders WHERE id = $1 AND user_email = $2',
      [req.params.id, email]
    );
    if (orderRes.rows.length === 0) return res.status(404).json({ error: 'Order not found' });
    const order = orderRes.rows[0];
    if (order.status !== 'Processing') return res.status(400).json({ error: 'Only Processing orders can be cancelled.' });

    await pool.query('UPDATE orders SET status = $1 WHERE id = $2', ['Cancelled', order.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ==========================================
// 11. COUPON ROUTES
// ==========================================

// POST: Validate a coupon code
app.post('/api/coupons/validate', async (req, res) => {
  try {
    const { code, orderAmount } = req.body;
    const result = await pool.query(
      `SELECT * FROM coupons WHERE UPPER(code) = UPPER($1) AND is_active = true
       AND (expires_at IS NULL OR expires_at > NOW())
       AND (max_uses IS NULL OR uses < max_uses)`,
      [code]
    );
    if (result.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired coupon.' });
    const coupon = result.rows[0];
    if (parseFloat(orderAmount) < parseFloat(coupon.min_order_amount))
      return res.status(400).json({ error: `Minimum order amount ₹${coupon.min_order_amount} required.` });

    const discount = coupon.discount_type === 'percent'
      ? Math.round((parseFloat(orderAmount) * parseFloat(coupon.discount_value)) / 100)
      : parseFloat(coupon.discount_value);

    res.json({ valid: true, discount, discount_type: coupon.discount_type, discount_value: coupon.discount_value, code: coupon.code });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Create coupon
app.post('/api/admin/coupons', authenticateAdmin, async (req, res) => {
  try {
    const { code, discount_type, discount_value, min_order_amount, max_uses, expires_at } = req.body;
    const result = await pool.query(
      `INSERT INTO coupons (code, discount_type, discount_value, min_order_amount, max_uses, expires_at)
       VALUES (UPPER($1), $2, $3, $4, $5, $6) RETURNING *`,
      [code, discount_type, discount_value, min_order_amount || 0, max_uses || null, expires_at || null]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: List all coupons
app.get('/api/admin/coupons', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM coupons ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Toggle coupon active state
app.put('/api/admin/coupons/:id', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'UPDATE coupons SET is_active = NOT is_active WHERE id = $1 RETURNING *',
      [req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ==========================================
// 12. STOCK NOTIFICATION ROUTES
// ==========================================

// POST: Save notify-me email for an out-of-stock product
app.post('/api/notify-me', async (req, res) => {
  try {
    const { email, product_id } = req.body;
    if (!email || !product_id) return res.status(400).json({ error: 'email and product_id are required.' });
    // Upsert — ignore duplicate (same email + product)
    await pool.query(
      `INSERT INTO stock_notifications (email, product_id) VALUES ($1, $2)
       ON CONFLICT (email, product_id) DO NOTHING`,
      [email, parseInt(product_id, 10)]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET: Admin — all pending stock notifications
app.get('/api/admin/stock-notifications', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT sn.id, sn.email, sn.product_id, sn.created_at, p.title as product_title
       FROM stock_notifications sn
       JOIN products p ON p.id = sn.product_id
       ORDER BY sn.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ==========================================
// 13. RETURN REQUEST ROUTES
// ==========================================

// POST: Submit a return request (only for Delivered orders)
app.post('/api/returns', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { order_id, order_number, reason, comments } = req.body;
    if (!order_id || !reason) return res.status(400).json({ error: 'order_id and reason are required.' });

    // Verify the order belongs to this user and is Delivered
    const userRes = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const orderRes = await pool.query(
      "SELECT id FROM orders WHERE id = $1 AND user_email = $2 AND status = 'Delivered'",
      [order_id, userRes.rows[0].email]
    );
    if (orderRes.rows.length === 0)
      return res.status(400).json({ error: 'Only delivered orders can be returned.' });

    // Prevent duplicate return request
    const existing = await pool.query('SELECT id FROM returns WHERE order_id = $1 AND user_id = $2', [order_id, userId]);
    if (existing.rows.length > 0)
      return res.status(400).json({ error: 'A return request already exists for this order.' });

    const result = await pool.query(
      'INSERT INTO returns (order_id, order_number, user_id, reason, comments) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [order_id, order_number, userId, reason, comments || null]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET: Fetch all return requests for the logged-in user
app.get('/api/returns', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM returns WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET: Admin — all return requests
app.get('/api/admin/returns', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT r.*, u.name as user_name, u.email as user_email FROM returns r
       JOIN users u ON r.user_id = u.id ORDER BY r.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT: Admin — update return status
app.put('/api/admin/returns/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const result = await pool.query(
      'UPDATE returns SET status = $1 WHERE id = $2 RETURNING *',
      [status, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 14. RAZORPAY PAYMENT ROUTES
// ==========================================

// POST: Create Razorpay Order
app.post('/api/payment/create-order', authenticateToken, validateRequest, async (req, res) => {
  if (!razorpay) return res.status(503).json({ error: 'Payment gateway not configured' });
  try {
    const { amount, currency = 'INR', receipt } = req.body;
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    // Create Razorpay order
    const options = {
      amount: Math.round(amount * 100), // Convert to paise
      currency,
      receipt: receipt || `order_${Date.now()}`,
      payment_capture: 1 // Auto capture
    };

    const order = await razorpay.orders.create(options);
    
    res.json({
      success: true,
      order_id: order.id,
      amount: order.amount,
      currency: order.currency,
      key_id: process.env.RAZORPAY_KEY_ID
    });
  } catch (err) {
    console.error('Razorpay Order Creation Error:', err);
    res.status(500).json({ error: 'Failed to create payment order' });
  }
});

// POST: Verify Razorpay Payment Signature
app.post('/api/payment/verify', authenticateToken, validateRequest, async (req, res) => {
  if (!razorpay) return res.status(503).json({ error: 'Payment gateway not configured' });
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ error: 'Missing payment details' });
    }

    // Verify signature
    const sign = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSign = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(sign.toString())
      .digest('hex');

    if (razorpay_signature === expectedSign) {
      // Fetch payment details from Razorpay
      const payment = await razorpay.payments.fetch(razorpay_payment_id);
      
      res.json({
        success: true,
        verified: true,
        payment_id: razorpay_payment_id,
        order_id: razorpay_order_id,
        amount: payment.amount / 100, // Convert from paise
        status: payment.status,
        method: payment.method
      });
    } else {
      res.status(400).json({ error: 'Invalid payment signature', verified: false });
    }
  } catch (err) {
    console.error('Payment Verification Error:', err);
    res.status(500).json({ error: 'Payment verification failed' });
  }
});

// POST: Get Payment Status
app.post('/api/payment/status', authenticateToken, async (req, res) => {
  if (!razorpay) return res.status(503).json({ error: 'Payment gateway not configured' });
  try {
    const { payment_id } = req.body;
    
    if (!payment_id) {
      return res.status(400).json({ error: 'Payment ID required' });
    }

    const payment = await razorpay.payments.fetch(payment_id);
    
    res.json({
      success: true,
      payment_id: payment.id,
      order_id: payment.order_id,
      amount: payment.amount / 100,
      status: payment.status,
      method: payment.method,
      captured: payment.captured,
      created_at: payment.created_at
    });
  } catch (err) {
    console.error('Payment Status Error:', err);
    res.status(500).json({ error: 'Failed to fetch payment status' });
  }
});

// ==========================================
// GLOBAL ERROR HANDLER
// ==========================================
app.use((err, req, res, next) => {
  if (err === invalidCsrfTokenError) {
    res.status(403).json({ error: "Invalid CSRF token" });
  } else if (err) {
    // Log the full error for your own debugging
    console.error("UNHANDLED_ERROR:", err.stack || err);

    // Send a generic, safe error message to the client in production
    if (process.env.NODE_ENV === 'production') {
      return res.status(500).json({ error: 'An internal server error occurred.' });
    }
    // In development, you might want to send the stack trace
    res.status(500).json({ error: 'An internal server error occurred.', details: err.message });
  } else {
    next(err);
  }
});

// ==========================================
// START SERVER
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  console.log(`Creative Kids backend is running securely on port ${PORT}`);
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS stock_notifications (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      product_id INTEGER NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(email, product_id)
    )`);
    console.log('stock_notifications table ready');
    // Auto-add missing columns if they don't exist
    await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS is_draft BOOLEAN DEFAULT false`);
    await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS closure_type TEXT`);
    await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS length_type TEXT`);
    await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS extra_categories JSONB DEFAULT '[]'`);
    await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS color_images JSONB DEFAULT '{}'`);
    await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS homepage_card_slot INTEGER`);
    console.log('Schema migrations complete');
  } catch (e) {
    console.error('Table init error:', e.message);
  }
});