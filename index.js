require('dotenv').config();

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const pool = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const nodemailer = require('nodemailer');
const Razorpay = require('razorpay');

const app = express();

// Trust App Runner / ALB proxy
app.set('trust proxy', 1);

// Security headers via helmet (all protections enabled)
app.use(helmet());

// CSRF — lightweight token using HMAC (no external library)
// Real security is provided by JWT auth + strict CORS origin allowlist
const CSRF_SECRET = process.env.CSRF_SECRET || crypto.randomBytes(32).toString('hex');

const generateCsrfToken = (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  const sig = crypto.createHmac('sha256', CSRF_SECRET).update(token).digest('hex');
  const csrfToken = `${token}.${sig}`;
  res.cookie('__csrf', csrfToken, { httpOnly: false, sameSite: 'lax', path: '/', secure: process.env.NODE_ENV === 'production' });
  return csrfToken;
};

const validateRequest = (req, res, next) => {
  // Skip CSRF for GET/HEAD/OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const token = req.headers['x-csrf-token'] || '';
  if (!token || token === 'none') return next(); // No token = skip (JWT auth is the real guard)
  const [raw, sig] = token.split('.');
  if (!raw || !sig) return next();
  try {
    const expected = crypto.createHmac('sha256', CSRF_SECRET).update(raw).digest('hex');
    if (sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
      return next();
    }
  } catch {}
  next(); // Fail open — JWT is the real security layer
};

const invalidCsrfTokenError = null;

// Middleware (Updated CORS for AWS Amplify and Custom Domains)
app.use(cors({
    origin: [
      'http://localhost:3000',
      'http://localhost:3001',
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

// Rate limiting
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts. Try again in 15 minutes.' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use('/api/auth', authLimiter);
app.use('/api/admin/login', authLimiter);
app.use('/api', apiLimiter);

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

if ((process.env.RAZORPAY_KEY_ID || process.env.key_id) && (process.env.RAZORPAY_KEY_SECRET || process.env.key_secret)) {
  razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || process.env.key_id,
    key_secret: process.env.RAZORPAY_KEY_SECRET || process.env.key_secret
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

// GET: All Products (only active, published, non-draft ones for storefront)
app.get('/api/products', async (req, res) => {
  try {
    const { sub_category, main_category, new_arrival, q, item_type, baby_all, kids_all,
            sizes, colors, fabrics, patterns, necks, price_min, price_max } = req.query;
    let query = `SELECT * FROM products WHERE is_active = true AND (is_draft = false OR is_draft IS NULL)`;
    const values = [];

    // Category filters — handle both new format (Baby boys/Girls clothing) and legacy (Baby/Kids)
    if (baby_all === 'true') {
      query += ` AND main_category IN ('Baby boys', 'Baby girls', 'Baby')`;
    } else if (kids_all === 'true') {
      query += ` AND main_category IN ('Boys clothing', 'Girls clothing', 'Kids')`;
    } else if (main_category) {
      // Map legacy values to new format for filtering
      const legacyMap = {
        'Baby boys':     ["Baby boys", "Baby"],
        'Baby girls':    ["Baby girls", "Baby"],
        'Boys clothing': ["Boys clothing", "Kids"],
        'Girls clothing':["Girls clothing", "Kids"],
      };
      const matchValues = legacyMap[main_category] || [main_category];
      values.push(...matchValues);
      const placeholders = matchValues.map((_, i) => `$${values.length - matchValues.length + 1 + i}`);
      query += ` AND main_category IN (${placeholders.join(', ')})`;
    }

    // Item type filter — checks item_type, sub_category, and category columns
    if (item_type) {
      // If item_type is a number (legacy bug), skip the filter — return all products in category
      if (/^\d+$/.test(item_type)) {
        // numeric item_type means old data — don't filter by it, just return category products
      } else {
        values.push(item_type);
        const ph = `$${values.length}`;
        query += ` AND (item_type = ${ph} OR sub_category = ${ph} OR category = ${ph})`;
      }
    } else if (sub_category) {
      values.push(sub_category);
      query += ` AND (sub_category = $${values.length} OR category = $${values.length})`;
    }

    // Price range
    if (price_min) { values.push(parseFloat(price_min)); query += ` AND price::numeric >= $${values.length}`; }
    if (price_max) { values.push(parseFloat(price_max)); query += ` AND price::numeric <= $${values.length}`; }

    // Fabric filter
    if (fabrics) {
      const fabricList = fabrics.split(',').map(f => f.trim()).filter(Boolean);
      if (fabricList.length > 0) {
        values.push(fabricList);
        query += ` AND fabric = ANY($${values.length}::text[])`;
      }
    }

    // Pattern filter
    if (patterns) {
      const patternList = patterns.split(',').map(p => p.trim()).filter(Boolean);
      if (patternList.length > 0) {
        values.push(patternList);
        query += ` AND pattern = ANY($${values.length}::text[])`;
      }
    }

    // Neck type filter
    if (necks) {
      const neckList = necks.split(',').map(n => n.trim()).filter(Boolean);
      if (neckList.length > 0) {
        values.push(neckList);
        query += ` AND neck_type = ANY($${values.length}::text[])`;
      }
    }

    // Color filter (color is a top-level column)
    if (colors) {
      const colorList = colors.split(',').map(c => c.trim()).filter(Boolean);
      if (colorList.length > 0) {
        values.push(colorList);
        query += ` AND color = ANY($${values.length}::text[])`;
      }
    }

    // Size filter (sizes stored as JSON array — check if any selected size is in the array)
    if (sizes) {
      const sizeList = sizes.split(',').map(s => s.trim()).filter(Boolean);
      if (sizeList.length > 0) {
        const sizeClauses = sizeList.map(s => {
          values.push(`%${s}%`);
          return `sizes::text ILIKE $${values.length}`;
        });
        query += ` AND (${sizeClauses.join(' OR ')})`;
      }
    }
    if (new_arrival === 'true') {
      query += ` AND is_new_arrival = true`;
    }
    if (q) {
      values.push(`%${q}%`);
      query += ` AND (title ILIKE $${values.length} OR description ILIKE $${values.length} OR color ILIKE $${values.length} OR main_category ILIKE $${values.length})`;
    }
    query += ` ORDER BY id DESC LIMIT 120;`;
    const allProducts = await pool.query(query, values);
    res.json(allProducts.rows);
  } catch (err) {
    console.error("Products GET Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
})

// GET: Single Product by ID — only active products
app.get('/api/products/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!id || id <= 0) return res.status(400).json({ message: "Invalid product ID" });
    const product = await pool.query(
      `SELECT * FROM products WHERE id = $1 AND is_active = true`,
      [id]
    );
    if (product.rows.length === 0) return res.status(404).json({ message: "Product not found" });
    res.json(product.rows[0]);
  } catch (err) {
    console.error("Single Product GET Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
})

// GET: Sibling products by variant_group_id (for color swatches)
app.get('/api/products/group/:groupId', async (req, res) => {
  try {
    const { groupId } = req.params;
    if (!groupId || groupId === 'undefined') return res.status(400).json({ message: "Invalid group ID" });

    const siblings = await pool.query(
      `SELECT id, color, image_urls, sku FROM products WHERE variant_group_id = $1 AND is_active = true`,
      [groupId]
    );
    res.json(siblings.rows);
  } catch (err) {
    console.error("Group GET Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// POST: Add new product (Grouped Architecture)
app.post("/api/products", authenticateAdmin, validateRequest, async (req, res) => {
  const client = await pool.connect();
  try {
    const {
      title, description, price, mrp, sizes, colors, is_featured, is_new_arrival, homepage_section, homepage_card_slot,
      sku: baseSku, hsn_code, fabric, pattern, neck_type, belt_included,
      closure_type, length_type,
      manufacturer_details, care_instructions, origin_country,
      primary_category, main_category, sub_category, item_type, variants, cross_listed_categories, extra_categories, color_images,
      is_draft, is_cod_eligible, weight
    } = req.body;

    // Validate product data
    const validationError = validateProductData(req.body, is_draft);
    if (validationError) return res.status(400).json({ error: validationError });

    await client.query('BEGIN');
    
    const variantGroupId = crypto.randomUUID();
    const createdProducts = [];
    
    const finalMainCat = primary_category || main_category || 'Uncategorized';
    const finalSubCat = item_type || sub_category || 'Uncategorized';
    const finalCrossListed = cross_listed_categories || extra_categories || [];

    // Insert a distinct row for every color
    for (const color of (colors || [])) {
      const colorCode = color.replace(/\s+/g, '').substring(0, 3).toUpperCase();
      const productSku = baseSku ? `${baseSku}-${colorCode}` : `SKU-${Date.now()}-${colorCode}`;
      
      const colorSpecificVariants = (variants || []).filter(v => v.color === color);
      const specificImageUrls = (color_images || {})[color] || [];

      const query = `
        INSERT INTO products (
          title, description, price, mrp, image_urls, sizes, colors, is_featured, is_new_arrival, homepage_section, homepage_card_slot,
          sku, hsn_code, fabric, pattern, neck_type, belt_included, closure_type, length_type,
          manufacturer_details, care_instructions, origin_country,
          main_category, sub_category, item_type, category, variants, extra_categories, color_images, is_draft, variant_group_id, color
        ) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32) 
        RETURNING *;
      `;

      const values = [
        `${title} - ${color}`, description, price, mrp, 
        JSON.stringify(specificImageUrls), JSON.stringify(sizes), JSON.stringify(colors), 
        is_featured, is_new_arrival, homepage_section, homepage_card_slot,
        productSku, hsn_code, fabric, pattern, neck_type, belt_included,
        closure_type || null, length_type || null,
        manufacturer_details, care_instructions, origin_country,
        finalMainCat, finalSubCat, item_type, finalSubCat,
        JSON.stringify(colorSpecificVariants),
        JSON.stringify(finalCrossListed),
        JSON.stringify(color_images || {}),
        is_draft || false, variantGroupId, color
      ];

      const newProduct = await client.query(query, values);
      createdProducts.push(newProduct.rows[0]);
    }

    await client.query('COMMIT');
    // Return the first inserted product so the frontend succeeds gracefully
    res.json(createdProducts[0] || {});
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Product POST Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  } finally {
    client.release();
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

// PATCH: Update only the variants/stock for a product (lightweight — no full validation)
app.patch("/api/products/:id/stock", authenticateAdmin, validateRequest, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!id || id <= 0) return res.status(400).json({ error: "Invalid product ID" });
    const { variants } = req.body;
    if (!variants) return res.status(400).json({ error: "variants required" });
    await pool.query("UPDATE products SET variants = $1 WHERE id = $2", [JSON.stringify(variants), id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT: Update an existing product (Grouped Architecture)
app.put("/api/products/:id", authenticateAdmin, validateRequest, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const {
      title, description, price, mrp, sizes, colors, is_featured, is_new_arrival, homepage_section, homepage_card_slot,
      sku: baseSku, hsn_code, fabric, pattern, neck_type, belt_included,
      closure_type, length_type,
      manufacturer_details, care_instructions, origin_country,
      primary_category, main_category, sub_category, item_type, variants, cross_listed_categories, extra_categories, color_images,
      is_draft, is_cod_eligible, weight
    } = req.body;

    // Validate product data
    const validationError = validateProductData(req.body, is_draft);
    if (validationError) return res.status(400).json({ error: validationError });

    await client.query('BEGIN');

    // 1. Get the variant_group_id of the product being edited
    const currentProdRes = await client.query('SELECT variant_group_id FROM products WHERE id = $1', [id]);
    if (currentProdRes.rows.length === 0) throw new Error('Product not found');
    
    let variantGroupId = currentProdRes.rows[0].variant_group_id;
    
    // Backward Compatibility: Assign UUID if editing a legacy product without one
    if (!variantGroupId) {
      variantGroupId = crypto.randomUUID();
      await client.query('UPDATE products SET variant_group_id = $1 WHERE id = $2', [variantGroupId, id]);
    }

    const finalMainCat = primary_category || main_category || 'Uncategorized';
    const finalSubCat = item_type || sub_category || 'Uncategorized';
    const finalCrossListed = cross_listed_categories || extra_categories || [];
    const processedColors = [];

    // 2. Iterate through submitted colors
    for (const color of colors) {
      processedColors.push(color);
      
      const colorCode = color.replace(/\s+/g, '').substring(0, 3).toUpperCase();
      const productSku = baseSku ? `${baseSku}-${colorCode}` : `SKU-${Date.now()}-${colorCode}`;
      
      // Isolate this color's specific images and variants
      const colorSpecificVariants = (variants || []).filter(v => v.color === color);
      const specificImageUrls = (color_images || {})[color] || [];

      // Check if this color already exists in the group
      const existingRes = await client.query(
        'SELECT id FROM products WHERE variant_group_id = $1 AND color = $2',
        [variantGroupId, color]
      );

      if (existingRes.rows.length > 0) {
        // Update existing linked product
        const existingId = existingRes.rows[0].id;
        await client.query(`
          UPDATE products SET 
            title = $1, description = $2, price = $3, mrp = $4, image_urls = $5, sizes = $6, colors = $7, 
            is_featured = $8, is_new_arrival = $9, homepage_section = $10, homepage_card_slot = $11,
            sku = $12, hsn_code = $13, fabric = $14, pattern = $15, neck_type = $16, belt_included = $17,
            closure_type = $18, length_type = $19,
            manufacturer_details = $20, care_instructions = $21, origin_country = $22,
            main_category = $23, sub_category = $24, item_type = $25, category = $26, variants = $27,
            extra_categories = $28, color_images = $29, is_draft = $30, color = $31, is_active = true
          WHERE id = $32;
        `, [
          `${title} - ${color}`, description, price, mrp, 
          JSON.stringify(specificImageUrls), JSON.stringify(sizes), JSON.stringify(colors), 
          is_featured, is_new_arrival, homepage_section, homepage_card_slot,
          productSku, hsn_code, fabric, pattern, neck_type, belt_included,
          closure_type || null, length_type || null,
          manufacturer_details, care_instructions, origin_country,
          finalMainCat, finalSubCat, item_type, finalSubCat,
          JSON.stringify(colorSpecificVariants),
          JSON.stringify(finalCrossListed),
          JSON.stringify(color_images || {}),
          is_draft || false, color, existingId
        ]);
      } else {
        // Insert new linked product (New color added during edit)
        await client.query(`
          INSERT INTO products (
            title, description, price, mrp, image_urls, sizes, colors, is_featured, is_new_arrival, homepage_section, homepage_card_slot,
            sku, hsn_code, fabric, pattern, neck_type, belt_included, closure_type, length_type,
            manufacturer_details, care_instructions, origin_country,
            main_category, sub_category, item_type, category, variants, extra_categories, color_images, is_draft, variant_group_id, color
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32)
        `, [
          `${title} - ${color}`, description, price, mrp, 
          JSON.stringify(specificImageUrls), JSON.stringify(sizes), JSON.stringify(colors), 
          is_featured, is_new_arrival, homepage_section, homepage_card_slot,
          productSku, hsn_code, fabric, pattern, neck_type, belt_included,
          closure_type || null, length_type || null,
          manufacturer_details, care_instructions, origin_country,
          finalMainCat, finalSubCat, item_type, finalSubCat,
          JSON.stringify(colorSpecificVariants),
          JSON.stringify(finalCrossListed),
          JSON.stringify(color_images || {}),
          is_draft || false, variantGroupId, color
        ]);
      }
    }

    // 3. Soft-delete products in this group whose color was removed during the edit
    if (processedColors.length > 0) {
      await client.query(`
        UPDATE products SET is_active = false 
        WHERE variant_group_id = $1 AND color != ALL($2::text[])
      `, [variantGroupId, processedColors]);
    }

    await client.query('COMMIT');
    
    // Return one of the updated rows for the frontend
    const updatedProduct = await client.query('SELECT * FROM products WHERE id = $1', [id]);
    res.json(updatedProduct.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Product PUT Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  } finally {
    client.release();
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


// GET: Homepage data
app.get('/api/homepage', async (req, res) => {
  try {
    const base = `is_active = true AND (is_draft = false OR is_draft IS NULL)`;
    const [newArrivals, bestsellers, featured] = await Promise.all([
      pool.query(`SELECT * FROM products WHERE ${base} AND is_new_arrival = true ORDER BY created_at DESC LIMIT 4`),
      pool.query(`SELECT * FROM products WHERE ${base} ORDER BY id DESC LIMIT 4`),
      pool.query(`SELECT * FROM products WHERE ${base} AND is_featured = true ORDER BY id DESC LIMIT 8`)
    ]);
    res.json({ newArrivals: newArrivals.rows, bestsellers: bestsellers.rows, featured: featured.rows });
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
    const query = `
      SELECT 
        COALESCE(variant_group_id, id::text) as variant_group_id,
        MAX(id) as id,
        MAX(title) as title,
        MAX(sku) as base_sku,
        MAX(price::numeric) as price,
        MAX(mrp::numeric) as mrp,
        MAX(main_category) as main_category,
        MAX(sub_category) as sub_category,
        MAX(item_type) as item_type,
        bool_or(is_active) as is_active,
        bool_or(is_draft) as is_draft,
        MAX(created_at) as created_at,
        json_agg(
          json_build_object(
            'id', id,
            'color', color,
            'sku', sku,
            'image_urls', image_urls,
            'variants', variants,
            'is_active', is_active
          ) ORDER BY id ASC
        ) as child_variants
      FROM products
      GROUP BY COALESCE(variant_group_id, id::text)
      ORDER BY MAX(id) DESC;
    `;
    const allProducts = await pool.query(query);
    res.json(allProducts.rows);
  } catch (err) {
    console.error("Admin Products Error:", err.message);
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
    const { cartItems, address, paymentMethod, couponCode, discountAmount, paymentId, razorpayOrderId } = req.body;
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

      enrichedItems.push({ ...item, price: parseFloat(product.price), title: product.title, image: item.image || null });
    }

    // 2. Server-side coupon validation — never trust client-supplied discountAmount
    let serverDiscount = 0;
    if (couponCode) {
      const couponRes = await client.query(
        `SELECT * FROM coupons WHERE UPPER(code) = UPPER($1) AND is_active = true
         AND (expires_at IS NULL OR expires_at > NOW())
         AND (max_uses IS NULL OR uses < max_uses)`,
        [couponCode]
      );
      if (couponRes.rows.length > 0) {
        const c = couponRes.rows[0];
        if (serverTotal >= parseFloat(c.min_order_amount)) {
          serverDiscount = c.discount_type === 'percent'
            ? Math.round((serverTotal * parseFloat(c.discount_value)) / 100)
            : parseFloat(c.discount_value);
        }
      }
    }
    const finalAmount = Math.max(0, serverTotal - serverDiscount);

    // 3. Insert the order
    const result = await client.query(
      `INSERT INTO orders (user_id, total_amount, status, payment_method, customer_name, coupon_code, discount_amount, payment_id, razorpay_payment_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id;`,
      [req.user.id, finalAmount, 'Processing', paymentMethod, address.fullName, couponCode || null, serverDiscount, paymentId || null, razorpayOrderId || null]
    );
    const newId = result.rows[0].id;
    const orderNumber = `Creativekids-O-${String(newId).padStart(6, '0')}`;
    await client.query(`UPDATE orders SET order_number = $1 WHERE id = $2`, [orderNumber, newId]);
    // Store extended data in columns added by migration
    await client.query(`UPDATE orders SET phone = $1, items_count = $2, shipping_address = $3, items = $4, user_email = $5 WHERE id = $6`,
      [address.phone, enrichedItems.length, JSON.stringify(address), JSON.stringify(enrichedItems), userEmail, newId]
    ).catch(() => {});
    if (couponCode && serverDiscount > 0) {
      await client.query('UPDATE coupons SET uses = uses + 1 WHERE UPPER(code) = UPPER($1)', [couponCode]).catch(() => {});
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


// GET: Fetch user address
app.get('/api/user/address', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM addresses WHERE user_id = $1 ORDER BY is_default DESC, id ASC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST: Add new address
app.post('/api/user/address', authenticateToken, async (req, res) => {
  try {
    const { fullName, phone, houseNo, roadName, city, state, pincode, landmark, is_default } = req.body;
    if (!fullName || !phone || !houseNo || !roadName || !city || !state || !pincode)
      return res.status(400).json({ error: 'All required fields must be filled.' });
    // If setting as default, unset others
    if (is_default) await pool.query('UPDATE addresses SET is_default = false WHERE user_id = $1', [req.user.id]);
    const result = await pool.query(
      `INSERT INTO addresses (user_id, full_name, phone, house_no, road_name, city, state, pincode, landmark, is_default)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [req.user.id, fullName, phone, houseNo, roadName, city, state, pincode, landmark || '', is_default || false]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT: Update an address
app.put('/api/user/address/:id', authenticateToken, async (req, res) => {
  try {
    const { fullName, phone, houseNo, roadName, city, state, pincode, landmark, is_default } = req.body;
    const addrId = parseInt(req.params.id, 10);
    // Verify ownership
    const own = await pool.query('SELECT id FROM addresses WHERE id = $1 AND user_id = $2', [addrId, req.user.id]);
    if (own.rows.length === 0) return res.status(403).json({ error: 'Not your address.' });
    if (is_default) await pool.query('UPDATE addresses SET is_default = false WHERE user_id = $1', [req.user.id]);
    const result = await pool.query(
      `UPDATE addresses SET full_name=$1, phone=$2, house_no=$3, road_name=$4, city=$5, state=$6, pincode=$7, landmark=$8, is_default=$9
       WHERE id=$10 RETURNING *`,
      [fullName, phone, houseNo, roadName, city, state, pincode, landmark || '', is_default || false, addrId]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE: Remove an address
app.delete('/api/user/address/:id', authenticateToken, async (req, res) => {
  try {
    const addrId = parseInt(req.params.id, 10);
    const own = await pool.query('SELECT id FROM addresses WHERE id = $1 AND user_id = $2', [addrId, req.user.id]);
    if (own.rows.length === 0) return res.status(403).json({ error: 'Not your address.' });
    await pool.query('DELETE FROM addresses WHERE id = $1', [addrId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PATCH: Set an address as default
app.patch('/api/user/address/:id/default', authenticateToken, async (req, res) => {
  try {
    const addrId = parseInt(req.params.id, 10);
    const own = await pool.query('SELECT id FROM addresses WHERE id = $1 AND user_id = $2', [addrId, req.user.id]);
    if (own.rows.length === 0) return res.status(403).json({ error: 'Not your address.' });
    await pool.query('UPDATE addresses SET is_default = false WHERE user_id = $1', [req.user.id]);
    await pool.query('UPDATE addresses SET is_default = true WHERE id = $1', [addrId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
      SELECT p.id, p.title, p.price, p.mrp, p.image_urls, p.category
      FROM products p
      JOIN wishlist w ON p.id = w.product_id
      WHERE w.user_id = $1
      ORDER BY w.id DESC;
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


// POST: Admin manually trigger refund for a cancelled order
app.post('/api/admin/orders/:id/refund', authenticateAdmin, validateRequest, async (req, res) => {
  try {
    const orderId = parseInt(req.params.id, 10);
    const orderRes = await pool.query('SELECT * FROM orders WHERE id = $1', [orderId]);
    if (orderRes.rows.length === 0) return res.status(404).json({ error: 'Order not found' });
    const order = orderRes.rows[0];

    const paymentId = order.payment_id || order.razorpay_payment_id;
    if (!paymentId) return res.status(400).json({ error: 'No payment ID found for this order' });
    if (order.payment_method === 'COD') return res.status(400).json({ error: 'COD orders cannot be refunded via Razorpay' });
    if (!razorpay) return res.status(503).json({ error: 'Razorpay not configured' });

    const refund = await razorpay.payments.refund(paymentId, {
      amount: Math.round(parseFloat(order.total_amount) * 100),
      notes: { order_number: order.order_number, reason: 'Admin initiated refund' }
    });

    await pool.query(
      `UPDATE orders SET refund_id = $1, refund_status = 'Initiated', refund_amount = $2 WHERE id = $3`,
      [refund.id, parseFloat(order.total_amount), orderId]
    );

    res.json({ success: true, refund_id: refund.id, amount: parseFloat(order.total_amount) });
  } catch (err) {
    console.error('Manual Refund Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST: Cancel an order (user-initiated) + auto-refund if paid online
app.post('/api/orders/:id/cancel', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const userId = req.user.id;
    const { reason = 'Customer requested cancellation' } = req.body;

    const userRes = await client.query('SELECT email FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const email = userRes.rows[0].email;

    const orderRes = await client.query(
      'SELECT * FROM orders WHERE id = $1 AND user_email = $2',
      [req.params.id, email]
    );
    if (orderRes.rows.length === 0) return res.status(404).json({ error: 'Order not found' });
    const order = orderRes.rows[0];

    // Only allow cancellation before shipping
    if (['Shipped', 'Delivered'].includes(order.status)) {
      return res.status(400).json({ error: 'Order cannot be cancelled after it has been shipped. Please raise a return request instead.' });
    }
    if (order.status === 'Cancelled') {
      return res.status(400).json({ error: 'Order is already cancelled.' });
    }

    await client.query('BEGIN');

    // Cancel the order
    await client.query(
      `UPDATE orders SET status = 'Cancelled', cancel_reason = $1, cancelled_at = NOW() WHERE id = $2`,
      [reason, order.id]
    );

    // Restore stock for each item
    let items = [];
    try { items = typeof order.items === 'string' ? JSON.parse(order.items) : (order.items || []); } catch {}
    for (const item of items) {
      const productRes = await client.query('SELECT variants FROM products WHERE id = $1', [item.id]);
      if (productRes.rows.length > 0) {
        let variants = [];
        try { variants = typeof productRes.rows[0].variants === 'string' ? JSON.parse(productRes.rows[0].variants) : (productRes.rows[0].variants || []); } catch {}
        const restored = variants.map(v => {
          const colorMatch = v.color === (item.selectedColor || 'Default');
          const sizeMatch = v.size === (item.selectedSize || 'Default');
          if (colorMatch && sizeMatch) return { ...v, stock: (parseInt(v.stock) || 0) + (item.quantity || 1) };
          return v;
        });
        await client.query('UPDATE products SET variants = $1 WHERE id = $2', [JSON.stringify(restored), item.id]);
      }
    }

    // Razorpay refund if paid online
    let refundResult = null;
    const paymentId = order.payment_id || order.razorpay_payment_id;
    if (paymentId && order.payment_method !== 'COD' && razorpay) {
      try {
        const refund = await razorpay.payments.refund(paymentId, {
          amount: Math.round(parseFloat(order.total_amount) * 100), // paise
          notes: { reason, order_number: order.order_number }
        });
        await client.query(
          `UPDATE orders SET refund_id = $1, refund_status = 'Initiated', refund_amount = $2 WHERE id = $3`,
          [refund.id, parseFloat(order.total_amount), order.id]
        );
        refundResult = { id: refund.id, amount: parseFloat(order.total_amount), status: 'Initiated' };
      } catch (refundErr) {
        console.error('Razorpay refund error:', refundErr.message);
        // Don't fail the cancellation — log and handle manually
        await client.query(
          `UPDATE orders SET refund_status = 'Failed', refund_notes = $1 WHERE id = $2`,
          [refundErr.message, order.id]
        );
        refundResult = { error: 'Refund initiation failed. Will be processed manually within 2-3 business days.' };
      }
    }

    await client.query('COMMIT');

    res.json({
      success: true,
      cancelled: true,
      refund: order.payment_method === 'COD'
        ? null
        : refundResult || { message: 'No payment found to refund' },
      message: order.payment_method === 'COD'
        ? 'Order cancelled successfully.'
        : refundResult?.id
          ? `Order cancelled. Refund of ₹${order.total_amount} initiated — will reach your account in 5-7 business days.`
          : `Order cancelled. Refund will be processed manually within 2-3 business days.`
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Cancel Order Error:', err.message);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});


// POST: Admin change own password
app.post('/api/admin/change-password', authenticateAdmin, validateRequest, async (req, res) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2 AND role = $3', [hashed, req.admin.id, 'admin']);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
// 15. STORE SETTINGS ROUTES
// ==========================================

// GET: Fetch all store settings (public — storefront needs maintenance/cod/reviews flags)
app.get('/api/settings', async (req, res) => {
  try {
    const result = await pool.query('SELECT key, value FROM store_settings');
    const settings = {};
    result.rows.forEach(r => {
      try { settings[r.key] = JSON.parse(r.value); } catch { settings[r.key] = r.value; }
    });
    res.json(settings);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT: Save store settings (admin only)
app.put('/api/admin/settings', authenticateAdmin, validateRequest, async (req, res) => {
  try {
    const entries = Object.entries(req.body);
    for (const [key, value] of entries) {
      const serialized = typeof value === 'object' ? JSON.stringify(value) : String(value);
      await pool.query(
        `INSERT INTO store_settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
        [key, serialized]
      );
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
    const {
      order_id, order_number, reason, comments,
      refund_preference, bank_account_name, bank_account_number, bank_ifsc, bank_upi
    } = req.body;
    if (!order_id || !reason) return res.status(400).json({ error: 'order_id and reason are required.' });

    // Verify the order belongs to this user and is Delivered
    const userRes = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const orderRes = await pool.query(
      "SELECT id, payment_method, total_amount FROM orders WHERE id = $1 AND user_email = $2 AND status = 'Delivered'",
      [order_id, userRes.rows[0].email]
    );
    if (orderRes.rows.length === 0)
      return res.status(400).json({ error: 'Only delivered orders can be returned.' });

    const order = orderRes.rows[0];

    // For COD orders, bank details are required
    if (order.payment_method === 'COD') {
      if (refund_preference === 'bank' && (!bank_account_name || !bank_account_number || !bank_ifsc)) {
        return res.status(400).json({ error: 'Bank account details are required for COD refunds.' });
      }
      if (refund_preference === 'upi' && !bank_upi) {
        return res.status(400).json({ error: 'UPI ID is required.' });
      }
    }

    // Prevent duplicate return request
    const existing = await pool.query('SELECT id FROM returns WHERE order_id = $1 AND user_id = $2', [order_id, userId]);
    if (existing.rows.length > 0)
      return res.status(400).json({ error: 'A return request already exists for this order.' });

    const result = await pool.query(
      `INSERT INTO returns (
        order_id, order_number, user_id, reason, comments, status,
        payment_method, refund_amount, refund_preference,
        bank_account_name, bank_account_number, bank_ifsc, bank_upi
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
      [
        order_id, order_number, userId, reason, comments || null, 'Pending',
        order.payment_method, parseFloat(order.total_amount),
        refund_preference || (order.payment_method === 'COD' ? 'bank' : 'razorpay'),
        bank_account_name || null, bank_account_number || null, bank_ifsc || null, bank_upi || null
      ]
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
// PUT: Admin — update return status with full workflow
app.put('/api/admin/returns/:id', authenticateAdmin, validateRequest, async (req, res) => {
  try {
    const returnId = parseInt(req.params.id, 10);
    const { status, pickup_awb } = req.body;

    const returnRes = await pool.query('SELECT * FROM returns WHERE id = $1', [returnId]);
    if (returnRes.rows.length === 0) return res.status(404).json({ error: 'Return not found' });
    const ret = returnRes.rows[0];

    let updateFields = { status };
    let refundResult = null;

    // When admin marks as "Verified" — product received and checked
    if (status === 'Verified') {
      updateFields.verified_at = new Date().toISOString();
    }

    // When admin marks as "Refund Initiated" — trigger actual refund
    if (status === 'Refund Initiated') {
      updateFields.refund_initiated_at = new Date().toISOString();

      if (ret.payment_method === 'COD') {
        // COD refund — bank transfer must be done manually (NEFT/UPI)
        // We just record it — admin does the actual bank transfer outside the system
        refundResult = {
          type: 'manual_bank_transfer',
          preference: ret.refund_preference,
          account_name: ret.bank_account_name,
          account_number: ret.bank_account_number,
          ifsc: ret.bank_ifsc,
          upi: ret.bank_upi,
          amount: ret.refund_amount,
          note: 'Please initiate NEFT/UPI transfer manually from your bank account'
        };
      } else {
        // Online payment — Razorpay refund
        const orderRes = await pool.query('SELECT * FROM orders WHERE id = $1', [ret.order_id]);
        if (orderRes.rows.length > 0) {
          const order = orderRes.rows[0];
          const paymentId = order.payment_id || order.razorpay_payment_id;
          if (paymentId && razorpay) {
            try {
              const refund = await razorpay.payments.refund(paymentId, {
                amount: Math.round(parseFloat(ret.refund_amount || order.total_amount) * 100),
                notes: { return_id: String(returnId), order_number: ret.order_number }
              });
              refundResult = { type: 'razorpay', refund_id: refund.id, amount: ret.refund_amount };
            } catch (e) {
              refundResult = { type: 'razorpay', error: e.message };
            }
          }
        }
      }
    }

    // Save pickup AWB if provided
    if (pickup_awb) updateFields.pickup_awb = pickup_awb;

    // Build update query dynamically
    const setClauses = Object.entries(updateFields).map(([k, v], i) => `${k} = $${i + 2}`);
    const values = [returnId, ...Object.values(updateFields)];
    const result = await pool.query(
      `UPDATE returns SET ${setClauses.join(', ')} WHERE id = $1 RETURNING *`,
      values
    );

    res.json({ ...result.rows[0], refund_details: refundResult });
  } catch (err) {
    console.error('Admin Returns Update Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 16. DELHIVERY SHIPPING ROUTES
// ==========================================

const DELHIVERY_BASE = 'https://track.delhivery.com';
const delhiveryHeaders = () => ({
  'Authorization': `Token ${process.env.DELHIVERY_API_TOKEN}`,
  'Content-Type': 'application/json',
  'Accept': 'application/json',
});

// POST: Create a Delhivery shipment for an order
app.post('/api/admin/orders/:id/ship', authenticateAdmin, validateRequest, async (req, res) => {
  try {
    const orderId = parseInt(req.params.id, 10);
    const { weight = 500, length = 20, breadth = 15, height = 10 } = req.body;

    // Fetch order details
    const orderRes = await pool.query('SELECT * FROM orders WHERE id = $1', [orderId]);
    if (orderRes.rows.length === 0) return res.status(404).json({ error: 'Order not found' });
    const order = orderRes.rows[0];

    if (order.awb_number) return res.status(400).json({ error: 'Shipment already created for this order' });

    let address = {};
    try { address = typeof order.shipping_address === 'string' ? JSON.parse(order.shipping_address) : (order.shipping_address || {}); } catch {}

    const warehouseName = process.env.DELHIVERY_WAREHOUSE_NAME || 'Creative Kids';

    // Build Delhivery shipment payload
    const shipmentData = {
      format: 'json',
      data: JSON.stringify({
        shipments: [{
          name: address.fullName || order.customer_name || 'Customer',
          add: `${address.houseNo || ''} ${address.roadName || ''}`.trim(),
          city: address.city || '',
          state: address.state || '',
          country: 'India',
          pin: address.pincode || '',
          phone: address.phone || order.phone || '',
          order: order.order_number || String(order.id),
          payment_mode: order.payment_method === 'COD' ? 'COD' : 'Prepaid',
          cod_amount: order.payment_method === 'COD' ? parseFloat(order.total_amount) : 0,
          total_amount: parseFloat(order.total_amount),
          weight: weight / 1000, // grams to kg
          shipment_length: length,
          shipment_width: breadth,
          shipment_height: height,
          seller_name: 'Creative Impression',
          seller_add: 'Plot No. 667, Pace City-II, Sector 37, Gurugram',
          seller_city: 'Gurugram',
          seller_state: 'Haryana',
          seller_country: 'India',
          seller_pin: '122001',
          seller_inv: order.order_number || String(order.id),
          quantity: order.items_count || 1,
          pickup_location: { name: warehouseName },
        }]
      })
    };

    // Create shipment on Delhivery
    const formBody = Object.entries(shipmentData).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
    const delhiveryRes = await fetch(`${DELHIVERY_BASE}/api/cmu/create.json`, {
      method: 'POST',
      headers: { ...delhiveryHeaders(), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formBody,
    });

    const delhiveryData = await delhiveryRes.json();

    if (!delhiveryRes.ok || delhiveryData.cod_error || delhiveryData.error) {
      console.error('Delhivery error:', delhiveryData);
      return res.status(400).json({ error: delhiveryData.error || delhiveryData.cod_error || 'Delhivery shipment creation failed' });
    }

    // Extract AWB from response
    const packages = delhiveryData.packages || [];
    const awb = packages[0]?.waybill || delhiveryData.waybill;
    if (!awb) return res.status(400).json({ error: 'No AWB returned from Delhivery', raw: delhiveryData });

    const trackingUrl = `https://www.delhivery.com/track/package/${awb}`;

    // Save AWB to order
    await pool.query(
      `UPDATE orders SET awb_number = $1, courier_name = $2, status = $3, tracking_url = $4 WHERE id = $5`,
      [awb, 'Delhivery', 'Shipped', trackingUrl, orderId]
    );

    res.json({ success: true, awb, tracking_url: trackingUrl });
  } catch (err) {
    console.error('Delhivery Ship Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST: Cancel a Delhivery shipment (only before pickup)
app.post('/api/admin/orders/:id/cancel-shipment', authenticateAdmin, validateRequest, async (req, res) => {
  try {
    const orderId = parseInt(req.params.id, 10);
    const orderRes = await pool.query('SELECT * FROM orders WHERE id = $1', [orderId]);
    if (orderRes.rows.length === 0) return res.status(404).json({ error: 'Order not found' });
    const order = orderRes.rows[0];

    if (!order.awb_number) return res.status(400).json({ error: 'No AWB found for this order' });

    // Cancel on Delhivery
    const body = new URLSearchParams();
    body.append('format', 'json');
    body.append('data', JSON.stringify({ waybill: order.awb_number, cancellation: 'true' }));

    const cancelRes = await fetch(`${DELHIVERY_BASE}/api/p/edit`, {
      method: 'POST',
      headers: { ...delhiveryHeaders(), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const cancelData = await cancelRes.json();

    // Update order in DB regardless (Delhivery may already have cancelled it)
    await pool.query(
      `UPDATE orders SET status = $1, awb_number = NULL, courier_name = NULL, tracking_url = NULL WHERE id = $2`,
      ['Cancelled', orderId]
    );

    res.json({ success: true, delhivery_response: cancelData });
  } catch (err) {
    console.error('Cancel Shipment Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/tracking/:awb', async (req, res) => {
  try {
    const { awb } = req.params;
    if (!awb || awb.length < 5) return res.status(400).json({ error: 'Invalid AWB' });
    const trackRes = await fetch(
      `${DELHIVERY_BASE}/api/v1/packages/json/?waybill=${awb}&verbose=true`,
      { headers: delhiveryHeaders() }
    );
    if (!trackRes.ok) return res.status(502).json({ error: 'Tracking service unavailable' });
    const data = await trackRes.json();
    const pkg = data.ShipmentData?.[0]?.Shipment;
    if (!pkg) return res.status(404).json({ error: 'Shipment not found' });
    const events = (pkg.Scans || []).map(s => ({
      status: s.ScanDetail?.Scan || '',
      location: s.ScanDetail?.ScannedLocation || '',
      time: s.ScanDetail?.ScanDateTime || '',
    })).reverse();
    res.json({
      awb, status: pkg.Status?.Status || 'In Transit',
      expected_delivery: pkg.ExpectedDeliveryDate || null,
      origin: pkg.Origin || '', destination: pkg.Destination || '',
      events,
    });
  } catch (err) {
    console.error('Tracking Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/delhivery/check/:pincode', async (req, res) => {
  try {
    const { pincode } = req.params;
    const checkRes = await fetch(
      `${DELHIVERY_BASE}/c/api/pin-codes/json/?filter_codes=${pincode}`,
      { headers: delhiveryHeaders() }
    );
    const data = await checkRes.json();
    const deliveryCode = data.delivery_codes?.[0];
    res.json({
      serviceable: !!deliveryCode,
      cod: deliveryCode?.postal_code?.cod === 'Y',
      prepaid: deliveryCode?.postal_code?.pre_paid === 'Y',
      pickup: deliveryCode?.postal_code?.pickup === 'Y',
    });
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
      key_id: process.env.RAZORPAY_KEY_ID || process.env.key_id
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
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || process.env.key_secret)
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
// 17. EASYECOM INTEGRATION
// ==========================================

const EASYECOM_BASE = 'https://api.easyecom.io';
let easyecomToken = null;
let easyecomTokenExpiry = null;

// Get/refresh EasyEcom JWT token
const getEasyEcomToken = async () => {
  if (easyecomToken && easyecomTokenExpiry && Date.now() < easyecomTokenExpiry) {
    return easyecomToken;
  }
  // Try without location_key first — EasyEcom may not require it for all accounts
  const body = {
    email: process.env.EASYECOM_EMAIL,
    password: process.env.EASYECOM_PASSWORD,
  };
  // Only add location_key if explicitly set
  if (process.env.EASYECOM_WAREHOUSE_CODE) {
    body.location_key = process.env.EASYECOM_WAREHOUSE_CODE;
  }
  const res = await fetch(`${EASYECOM_BASE}/access/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': process.env.EASYECOM_API_KEY,
    },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  console.log('EasyEcom token response:', JSON.stringify(data).slice(0, 400));
  if (!res.ok || !data.data?.jwt_token) throw new Error(data.message || JSON.stringify(data) || 'EasyEcom auth failed');
  easyecomToken = data.data.jwt_token;
  easyecomTokenExpiry = Date.now() + (23 * 60 * 60 * 1000);
  return easyecomToken;
};

const easyecomHeaders = async () => ({
  'Content-Type': 'application/json',
  'Authorization': `Bearer ${await getEasyEcomToken()}`,
  'x-api-key': process.env.EASYECOM_API_KEY,
});

// Fuzzy SKU match score (0-100)
const skuMatchScore = (a, b) => {
  if (!a || !b) return 0;
  const norm = s => s.toLowerCase().replace(/[-_\s]/g, '');
  const na = norm(a), nb = norm(b);
  if (na === nb) return 100;
  if (na.includes(nb) || nb.includes(na)) return 85;
  // Levenshtein distance
  const m = na.length, n = nb.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0));
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++) {
    dp[i][j] = na[i-1] === nb[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  }
  const maxLen = Math.max(m, n);
  return Math.round((1 - dp[m][n] / maxLen) * 100);
};

// POST: Connect EasyEcom (test credentials)
app.post('/api/admin/easyecom/connect', authenticateAdmin, validateRequest, async (req, res) => {
  try {
    easyecomToken = null; // force refresh
    // Debug: log what we're sending
    console.log('EasyEcom connect attempt:', {
      email: process.env.EASYECOM_EMAIL,
      location: process.env.EASYECOM_WAREHOUSE_CODE,
      hasKey: !!process.env.EASYECOM_API_KEY,
      hasPassword: !!process.env.EASYECOM_PASSWORD,
      passwordLength: process.env.EASYECOM_PASSWORD?.length || 0
    });
    const token = await getEasyEcomToken();
    await pool.query(`INSERT INTO store_settings (key, value) VALUES ('easyecom_connected', 'true') ON CONFLICT (key) DO UPDATE SET value = 'true'`);
    res.json({ success: true, message: 'EasyEcom connected successfully' });
  } catch (err) {
    console.error('EasyEcom connect error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

// GET: EasyEcom sync status
app.get('/api/admin/easyecom/status', authenticateAdmin, async (req, res) => {
  try {
    const [lastSync, mappings] = await Promise.all([
      pool.query(`SELECT value FROM store_settings WHERE key = 'easyecom_last_sync'`),
      pool.query(`SELECT status, COUNT(*) FROM sku_mappings GROUP BY status`),
    ]);
    const counts = {};
    mappings.rows.forEach(r => { counts[r.status] = parseInt(r.count); });
    res.json({
      connected: true,
      last_sync: lastSync.rows[0]?.value || null,
      mappings: counts,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST: Full sync — fetch all EasyEcom inventory and match/update
app.post('/api/admin/easyecom/sync', authenticateAdmin, async (req, res) => {
  try {
    const headers = await easyecomHeaders();
    const warehouseCode = process.env.EASYECOM_WAREHOUSE_CODE || '7210';

    // Fetch inventory from EasyEcom (paginated)
    let page = 1, allItems = [];
    while (true) {
      const invRes = await fetch(`${EASYECOM_BASE}/inventory/getInventoryByWarehouse`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ warehouse_code: warehouseCode, page_no: page, page_size: 100 })
      });
      const invData = await invRes.json();
      const items = invData.data?.inventory || invData.data || [];
      if (!Array.isArray(items) || items.length === 0) break;
      allItems = allItems.concat(items);
      if (items.length < 100) break;
      page++;
    }

    if (allItems.length === 0) return res.json({ success: true, message: 'No inventory data from EasyEcom', synced: 0 });

    // Build EasyEcom SKU → quantity map
    const easyecomMap = {};
    allItems.forEach(item => {
      const sku = item.sku || item.product_sku || item.item_sku;
      const qty = parseInt(item.available_quantity || item.quantity || item.available || 0);
      if (sku) easyecomMap[sku] = qty;
    });

    // Get all our products with their variants
    const products = await pool.query(`SELECT id, sku, variants FROM products WHERE is_active = true`);
    let synced = 0, unmatched = 0, updated = 0;

    for (const product of products.rows) {
      let variants = [];
      try { variants = typeof product.variants === 'string' ? JSON.parse(product.variants) : (product.variants || []); } catch {}

      let productUpdated = false;
      const updatedVariants = variants.map(v => {
        const variantSku = v.sku || product.sku;
        if (!variantSku) return v;

        // Try exact match first
        if (easyecomMap[variantSku] !== undefined) {
          const newStock = easyecomMap[variantSku];
          if (newStock !== parseInt(v.stock)) {
            // Log the change
            pool.query(
              `INSERT INTO inventory_sync_log (sku, source, old_stock, new_stock) VALUES ($1, 'easyecom', $2, $3)`,
              [variantSku, parseInt(v.stock) || 0, newStock]
            ).catch(() => {});
            productUpdated = true;
            synced++;
            return { ...v, stock: newStock };
          }
          return v;
        }

        // Try fuzzy match
        let bestSku = null, bestScore = 0;
        for (const eSku of Object.keys(easyecomMap)) {
          const score = skuMatchScore(variantSku, eSku);
          if (score > bestScore) { bestScore = score; bestSku = eSku; }
        }

        if (bestScore >= 85 && bestSku) {
          // Auto-confirm high confidence match
          pool.query(
            `INSERT INTO sku_mappings (internal_sku, easyecom_sku, match_score, status) VALUES ($1, $2, $3, 'confirmed')
             ON CONFLICT (internal_sku) DO UPDATE SET easyecom_sku = $2, match_score = $3, status = 'confirmed'`,
            [variantSku, bestSku, bestScore]
          ).catch(() => {});
          const newStock = easyecomMap[bestSku];
          productUpdated = true; synced++;
          return { ...v, stock: newStock };
        } else if (bestScore >= 50 && bestSku) {
          // Queue for review
          pool.query(
            `INSERT INTO sku_mappings (internal_sku, easyecom_sku, match_score, status) VALUES ($1, $2, $3, 'pending')
             ON CONFLICT (internal_sku) DO NOTHING`,
            [variantSku, bestSku, bestScore]
          ).catch(() => {});
          unmatched++;
        } else {
          // No match
          pool.query(
            `INSERT INTO sku_mappings (internal_sku, easyecom_sku, match_score, status) VALUES ($1, NULL, 0, 'unmatched')
             ON CONFLICT (internal_sku) DO NOTHING`,
            [variantSku]
          ).catch(() => {});
          unmatched++;
        }
        return v;
      });

      if (productUpdated) {
        await pool.query('UPDATE products SET variants = $1 WHERE id = $2', [JSON.stringify(updatedVariants), product.id]);
        updated++;
      }
    }

    // Save last sync time
    await pool.query(
      `INSERT INTO store_settings (key, value) VALUES ('easyecom_last_sync', $1) ON CONFLICT (key) DO UPDATE SET value = $1`,
      [new Date().toISOString()]
    );

    res.json({ success: true, synced, unmatched, products_updated: updated, easyecom_skus: Object.keys(easyecomMap).length });
  } catch (err) {
    console.error('EasyEcom Sync Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET: All SKU mappings (for reconciliation page)
app.get('/api/admin/sku-mappings', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM sku_mappings ORDER BY match_score DESC, created_at DESC');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT: Confirm or reject a SKU mapping
app.put('/api/admin/sku-mappings/:id', authenticateAdmin, validateRequest, async (req, res) => {
  try {
    const { status, easyecom_sku } = req.body; // status: 'confirmed' | 'rejected'
    const result = await pool.query(
      `UPDATE sku_mappings SET status = $1, easyecom_sku = COALESCE($2, easyecom_sku), last_synced_at = NOW() WHERE id = $3 RETURNING *`,
      [status, easyecom_sku || null, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Temp: inspect what category values exist in DB ──────────────────────────
app.get('/api/admin/debug/categories', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT item_type, sub_category, category, main_category, COUNT(*) as count
      FROM products
      GROUP BY item_type, sub_category, category, main_category
      ORDER BY count DESC
      LIMIT 50
    `);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
// GLOBAL ERROR HANDLER
// ==========================================
app.use((err, req, res, next) => {
  console.error("UNHANDLED_ERROR:", err.stack || err);
  if (process.env.NODE_ENV === 'production') {
    return res.status(500).json({ error: 'An internal server error occurred.' });
  }
  res.status(500).json({ error: 'An internal server error occurred.', details: err.message });
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
    await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS variant_group_id TEXT`);
    await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS color TEXT`);
    // Orders table columns
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_name TEXT`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS coupon_code TEXT`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS discount_amount NUMERIC DEFAULT 0`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS order_number TEXT`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS courier_name TEXT`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS awb_number TEXT`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS tracking_url TEXT`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_id TEXT`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS razorpay_payment_id TEXT`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS refund_id TEXT`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS refund_status TEXT`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS refund_amount NUMERIC`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS refund_notes TEXT`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS cancel_reason TEXT`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS cancelled_at TIMESTAMPTZ`);
    await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method TEXT`);
    // Wishlist table columns
    await pool.query(`ALTER TABLE wishlist ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT`);
    await pool.query(`CREATE TABLE IF NOT EXISTS addresses (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      full_name TEXT NOT NULL,
      phone TEXT NOT NULL,
      house_no TEXT NOT NULL,
      road_name TEXT NOT NULL,
      city TEXT NOT NULL,
      state TEXT NOT NULL,
      pincode TEXT NOT NULL,
      landmark TEXT DEFAULT '',
      is_default BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    console.log('Schema migrations complete');
    // EasyEcom tables
    await pool.query(`CREATE TABLE IF NOT EXISTS sku_mappings (
      id SERIAL PRIMARY KEY,
      internal_sku TEXT NOT NULL UNIQUE,
      easyecom_sku TEXT,
      match_score INTEGER DEFAULT 0,
      status TEXT DEFAULT 'pending',
      last_synced_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS inventory_sync_log (
      id SERIAL PRIMARY KEY,
      sku TEXT NOT NULL,
      source TEXT DEFAULT 'easyecom',
      old_stock INTEGER,
      new_stock INTEGER,
      synced_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    // Create store_settings table
    await pool.query(`CREATE TABLE IF NOT EXISTS store_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    // Insert defaults if not exist
    const defaults = [
      ['store_name', 'Creative Kids'],
      ['gstin', '06AAJPM1384L1ZE'],
      ['address', 'Plot No. 667, Pace City-II, Sector 37, Gurugram, Haryana – 122001'],
      ['support_email', 'support@creativekids.co.in'],
      ['maintenance_mode', 'false'],
      ['cod_enabled', 'true'],
      ['reviews_enabled', 'true'],
    ];
    for (const [key, value] of defaults) {
      await pool.query(
        `INSERT INTO store_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`,
        [key, value]
      );
    }
    // Fix legacy products where item_type was stored as a numeric string (old admin bug)
    // Use the category column (which has correct text) to fix item_type and sub_category
    await pool.query(`
      UPDATE products 
      SET item_type = category, sub_category = category
      WHERE item_type ~ '^[0-9]+$' AND category IS NOT NULL AND category != '' AND category != 'Uncategorized'
    `).catch(e => console.error('item_type fix error:', e.message));
    // Fix legacy main_category numeric values using category column
    await pool.query(`
      UPDATE products 
      SET main_category = category
      WHERE main_category ~ '^[0-9]+$' AND category IS NOT NULL AND category != ''
    `).catch(() => {});
    // Backfill item_type from sub_category for products with no item_type
    await pool.query(`
      UPDATE products SET item_type = sub_category
      WHERE (item_type IS NULL OR item_type = '') AND sub_category IS NOT NULL AND sub_category != '' AND sub_category != 'Uncategorized'
    `).catch(() => {});
    // Backfill main_category from category for legacy products
    await pool.query(`
      UPDATE products SET main_category = category
      WHERE (main_category IS NULL OR main_category = '') AND category IS NOT NULL AND category != ''
    `).catch(() => {});
    // Ensure returns table has status column
    await pool.query(`CREATE TABLE IF NOT EXISTS returns (
      id SERIAL PRIMARY KEY,
      order_id INTEGER NOT NULL,
      order_number TEXT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason TEXT NOT NULL,
      comments TEXT,
      status TEXT DEFAULT 'Pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`ALTER TABLE returns ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'Pending'`);
    await pool.query(`ALTER TABLE returns ADD COLUMN IF NOT EXISTS bank_account_name TEXT`);
    await pool.query(`ALTER TABLE returns ADD COLUMN IF NOT EXISTS bank_account_number TEXT`);
    await pool.query(`ALTER TABLE returns ADD COLUMN IF NOT EXISTS bank_ifsc TEXT`);
    await pool.query(`ALTER TABLE returns ADD COLUMN IF NOT EXISTS bank_upi TEXT`);
    await pool.query(`ALTER TABLE returns ADD COLUMN IF NOT EXISTS refund_preference TEXT DEFAULT 'bank'`);
    await pool.query(`ALTER TABLE returns ADD COLUMN IF NOT EXISTS pickup_awb TEXT`);
    await pool.query(`ALTER TABLE returns ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ`);
    await pool.query(`ALTER TABLE returns ADD COLUMN IF NOT EXISTS refund_initiated_at TIMESTAMPTZ`);
    await pool.query(`ALTER TABLE returns ADD COLUMN IF NOT EXISTS refund_amount NUMERIC`);
    await pool.query(`ALTER TABLE returns ADD COLUMN IF NOT EXISTS payment_method TEXT`);
  } catch (e) {
    console.error('Table init error:', e.message);
  }
});