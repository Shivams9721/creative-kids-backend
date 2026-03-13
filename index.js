const express = require('express');
const cors = require('cors');
const pool = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware (Updated CORS for Vercel)
app.use(cors({
    origin: [''http://localhost:3000', 
      'https://main.d1ucppcuwyaa0p.amplifyapp.com', // Your AWS Amplify link
      'https://creativekids.com',                   // Your NEW GoDaddy Domain
      'https://www.creativekids.com',                // (Add the www version too!)'
       'https://www.creativekids.co.in'], 
    credentials: true
}));
app.use(express.json());

// JWT Secret Key (Used for keeping users logged in safely)
const JWT_SECRET = process.env.JWT_SECRET || 'creative_kids_super_secret_key_123!';

// ==========================================
// 1. PRODUCT ROUTES
// ==========================================

// GET: All Products
app.get('/api/products', async (req, res) => {
  try {
    const query = `SELECT * FROM products ORDER BY id DESC;`;
    const allProducts = await pool.query(query);
    res.json(allProducts.rows);
  } catch (err) {
    console.error("Products GET Error:", err.message);
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// GET: Single Product by ID
app.get('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const query = `SELECT * FROM products WHERE id = $1;`;
    const product = await pool.query(query, [id]);

    if (product.rows.length === 0) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.json(product.rows[0]);
  } catch (err) {
    console.error("Single Product GET Error:", err.message);
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// POST: Add new product
app.post("/api/products", async (req, res) => {
  try {
    const {
      title, description, price, mrp, image_urls, sizes, colors, is_featured, is_new_arrival, homepage_section, homepage_card_slot,
      sku, hsn_code, fabric, pattern, neck_type, belt_included,
      manufacturer_details, care_instructions, origin_country,
      main_category, sub_category, item_type, variants
    } = req.body;

    const query = `
      INSERT INTO products (
        title, description, price, mrp, image_urls, sizes, colors, is_featured, is_new_arrival, homepage_section, homepage_card_slot,
        sku, hsn_code, fabric, pattern, neck_type, belt_included, 
        manufacturer_details, care_instructions, origin_country,
        main_category, sub_category, item_type, category, variants
      ) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25) 
      RETURNING *;
    `;

    const values = [
      title, description, price, mrp, image_urls, sizes, colors, is_featured, is_new_arrival, homepage_section, homepage_card_slot,
      sku, hsn_code, fabric, pattern, neck_type, belt_included,
      manufacturer_details, care_instructions, origin_country,
      main_category, sub_category, item_type, sub_category,
      JSON.stringify(variants)
    ];

    const newProduct = await pool.query(query, values);
    res.json(newProduct.rows[0]);
  } catch (err) {
    console.error("Product POST Error:", err.message);
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// PUT: Update an existing product
app.put("/api/products/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const {
      title, description, price, mrp, image_urls, sizes, colors, is_featured, is_new_arrival, homepage_section, homepage_card_slot,
      sku, hsn_code, fabric, pattern, neck_type, belt_included,
      manufacturer_details, care_instructions, origin_country,
      main_category, sub_category, item_type, variants
    } = req.body;

    const query = `
      UPDATE products SET 
        title = $1, description = $2, price = $3, mrp = $4, image_urls = $5, sizes = $6, colors = $7, 
        is_featured = $8, is_new_arrival = $9, homepage_section = $10, homepage_card_slot = $11,
        sku = $12, hsn_code = $13, fabric = $14, pattern = $15, neck_type = $16, belt_included = $17, 
        manufacturer_details = $18, care_instructions = $19, origin_country = $20,
        main_category = $21, sub_category = $22, item_type = $23, category = $24, variants = $25
      WHERE id = $26 RETURNING *;
    `;

    const values = [
      title, description, price, mrp, image_urls, sizes, colors, is_featured, is_new_arrival, homepage_section, homepage_card_slot,
      sku, hsn_code, fabric, pattern, neck_type, belt_included,
      manufacturer_details, care_instructions, origin_country,
      main_category, sub_category, item_type, sub_category,
      JSON.stringify(variants), id
    ];

    const updatedProduct = await pool.query(query, values);
    res.json(updatedProduct.rows[0]);
  } catch (err) {
    console.error("Product PUT Error:", err.message);
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// DELETE: Remove a product entirely
app.delete("/api/products/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query("DELETE FROM products WHERE id = $1", [id]);
    res.json({ message: "Product deleted successfully" });
  } catch (err) {
    console.error("Delete Product Error:", err.message);
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// ==========================================
// 2. ADMIN DASHBOARD ROUTES
// ==========================================

// GET: Live stats for the Admin Overview Panel
app.get("/api/admin/stats", async (req, res) => {
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
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// ==========================================
// 3. ORDER ROUTES (ADVANCED)
// ==========================================

// POST: Create a new order from Checkout
app.post("/api/orders", async (req, res) => {
  try {
    const { cartItems, totalAmount, address, paymentMethod, userEmail } = req.body;

    const insertQuery = `
      INSERT INTO orders (customer_name, phone, total_amount, items_count, status, shipping_address, items, payment_method, user_email)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id;
    `;
    const values = [
      address.fullName, address.phone, totalAmount, cartItems.length,
      'Processing', JSON.stringify(address), JSON.stringify(cartItems), paymentMethod, userEmail || 'guest'
    ];

    const result = await pool.query(insertQuery, values);
    const newId = result.rows[0].id;

    const orderNumber = `Creativekids-O-${String(newId).padStart(6, '0')}`;

    await pool.query(`UPDATE orders SET order_number = $1 WHERE id = $2`, [orderNumber, newId]);

    res.json({ success: true, order_number: orderNumber });
  } catch (err) {
    console.error("Create Order Error:", err.message);
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// Fetch orders specifically for the logged-in customer's profile
app.get("/api/orders/user/:email", async (req, res) => {
  try {
    const { email } = req.params;
    const result = await pool.query("SELECT * FROM orders WHERE user_email = $1 ORDER BY id DESC", [email]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 4. AUTHENTICATION & USER ROUTES
// ==========================================

// Register a New User
app.post("/api/auth/register", async (req, res) => {
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
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// Login an Existing User
app.post("/api/auth/login", async (req, res) => {
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
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// ==========================================
// 5. SECURE USER PROFILE ROUTES
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

// GET: Fetch ONLY the logged-in user's orders
app.get('/api/user/orders', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const userOrders = await pool.query(
      "SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC",
      [userId]
    );
    res.json(userOrders.rows);
  } catch (err) {
    console.error("User Orders GET Error:", err.message);
    res.status(500).json({ error: "Server Error", details: err.message });
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
    res.status(500).json({ error: "Server Error", details: err.message });
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
    res.status(500).json({ error: "Server Error", details: err.message });
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
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// ==========================================
// 7. SECURE ADMIN AUTHENTICATION
// ==========================================
app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const ADMIN_EMAIL = "admin@creativekids.com";
    const ADMIN_PASSWORD = "admin";

    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
      const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "12h" });
      res.json({ success: true, token });
    } else {
      res.status(401).json({ error: "Unauthorized", message: "Invalid Admin Credentials" });
    }
  } catch (err) {
    console.error("Admin Login Error:", err.message);
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// ==========================================
// DEDICATED ADMIN ORDER ROUTES 
// ==========================================

// 1. Fetch all orders (specifically for the Admin Dashboard)
app.get("/api/admin/orders", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM orders ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    console.error("Admin Fetch Orders Error:", err.message);
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// 2. Update order status (specifically for the Admin Dashboard)
app.put("/api/admin/orders/:id/status", async (req, res) => {
  try {
    const { status } = req.body;
    const result = await pool.query(
      "UPDATE orders SET status = $1 WHERE id = $2 RETURNING *", 
      [status, req.params.id]
    );
    res.json({ success: true, order: result.rows[0] });
  } catch (err) {
    console.error("Admin Update Status Error:", err.message);
    res.status(500).json({ error: "Server Error", details: err.message });
  }
});

// ==========================================
// START SERVER
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Creative Kids backend is running securely on port ${PORT}`);
});