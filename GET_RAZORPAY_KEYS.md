# 🔑 GET YOUR RAZORPAY API KEYS - Step by Step

## ✅ Razorpay SDK Installed Successfully!

Now you need to get your API keys from Razorpay dashboard.

---

## 📋 STEP-BY-STEP GUIDE

### **STEP 1: Sign Up / Login to Razorpay**

1. Go to: **https://razorpay.com**
2. Click **"Sign Up"** (or "Login" if you have an account)
3. Use **Google Sign-in** for fastest signup
4. Complete basic details (name, email, phone)

---

### **STEP 2: Access Dashboard**

1. After login, you'll be on the **Dashboard**
2. You'll see a banner saying **"Test Mode"** (this is good for development)
3. Look for the left sidebar menu

---

### **STEP 3: Generate API Keys**

1. In the left sidebar, click **"Settings"** (gear icon at bottom)
2. Click **"API Keys"** from the settings menu
3. You'll see a section **"Test Keys"**
4. Click **"Generate Test Keys"** button
5. A modal will appear with:
   - **Key ID** (starts with `rzp_test_`)
   - **Key Secret** (long alphanumeric string)

---

### **STEP 4: Copy Your Keys**

**Key ID Example:**
```
rzp_test_1234567890abcd
```

**Key Secret Example:**
```
abcdefghijklmnopqrstuvwxyz123456
```

⚠️ **IMPORTANT:** 
- Keep Key Secret **CONFIDENTIAL**
- Never commit it to Git
- Never share it publicly

---

### **STEP 5: Add Keys to Backend .env**

1. Open: `creative-kids-backend/.env`
2. Find these lines:
   ```env
   RAZORPAY_KEY_ID=rzp_test_YOUR_KEY_ID_HERE
   RAZORPAY_KEY_SECRET=YOUR_KEY_SECRET_HERE
   ```
3. Replace with your actual keys:
   ```env
   RAZORPAY_KEY_ID=rzp_test_1234567890abcd
   RAZORPAY_KEY_SECRET=abcdefghijklmnopqrstuvwxyz123456
   ```
4. **Save the file**

---

### **STEP 6: Restart Backend Server**

```bash
cd creative-kids-backend
npm run dev
```

You should see in the console:
```
Creative Kids backend is running securely on port 5000
```

If you see a warning about Razorpay credentials, check your `.env` file again.

---

## 🧪 TEST YOUR INTEGRATION

### **1. Start Frontend**
```bash
cd creative-kids-frontend
npm run dev
```

### **2. Test Payment Flow**

1. Open: http://localhost:3000
2. Add any product to cart
3. Click "Checkout"
4. Fill address details
5. Select **"UPI"** or **"Credit / Debit Card"**
6. Click **"Confirm & Pay"**
7. Razorpay modal should open ✅

### **3. Use Test Credentials**

**For Card Payment:**
```
Card Number: 4111 1111 1111 1111
Expiry: 12/25 (any future date)
CVV: 123
Name: Test User
```

**For UPI Payment:**
```
UPI ID: success@razorpay
```

### **4. Complete Payment**

1. Enter test credentials
2. Click "Pay"
3. Payment should succeed ✅
4. Order should be created ✅
5. You'll be redirected to success page ✅

---

## ✅ VERIFICATION CHECKLIST

After testing, verify:

- [ ] Razorpay modal opened
- [ ] Payment completed successfully
- [ ] Order created in database
- [ ] Order visible in user profile
- [ ] Success page shows order details
- [ ] Invoice can be downloaded

---

## 🎯 CHECK RAZORPAY DASHBOARD

After successful payment:

1. Go back to Razorpay Dashboard
2. Click **"Transactions"** in left sidebar
3. You should see your test payment ✅
4. Click on it to see details:
   - Amount
   - Payment method
   - Status (Captured)
   - Customer details

---

## 🚨 TROUBLESHOOTING

### **Issue: "Failed to load payment gateway"**

**Check:**
1. Are keys added to `.env`?
2. Did you restart backend server?
3. Check browser console for errors

**Solution:**
```bash
# Restart backend
cd creative-kids-backend
npm run dev
```

### **Issue: "Payment verification failed"**

**Check:**
1. Is `RAZORPAY_KEY_SECRET` correct in `.env`?
2. No extra spaces in `.env` file?
3. Check backend console for errors

**Solution:**
- Copy-paste keys again carefully
- Restart backend server

### **Issue: Keys not working**

**Check:**
1. Are you using **Test Keys** (not Live Keys)?
2. Test keys start with `rzp_test_`
3. Did you save `.env` file?

---

## 📊 RAZORPAY DASHBOARD SECTIONS

### **Important Tabs:**

1. **Dashboard** - Overview of transactions
2. **Transactions** - All payments (test & live)
3. **Orders** - Razorpay orders created
4. **Settlements** - Money transfers (live mode only)
5. **Customers** - Customer database
6. **Reports** - Download transaction reports

---

## 🎉 NEXT STEPS

### **After Testing Successfully:**

1. ✅ Test multiple payment methods (UPI, Card, Netbanking)
2. ✅ Test payment failure scenarios
3. ✅ Test order creation after payment
4. ✅ Test invoice download

### **Before Going Live:**

1. **Complete KYC:**
   - Go to Settings → Account & Settings
   - Submit business documents
   - Bank account verification
   - Wait for approval (1-2 days)

2. **Generate Live Keys:**
   - Settings → API Keys
   - Switch to "Live Mode"
   - Generate Live Keys
   - Update `.env` with live keys

3. **Enable Payment Methods:**
   - Settings → Payment Methods
   - Enable Cards, UPI, Netbanking, Wallets
   - Set up auto-settlement

4. **Test with Real Money:**
   - Make a small test transaction (₹10)
   - Verify it appears in dashboard
   - Check settlement schedule

---

## 💰 PRICING (India)

- **UPI:** FREE (limited time offer)
- **Domestic Cards:** 2% + GST
- **International Cards:** 3% + GST
- **Netbanking:** ₹10 + GST per transaction
- **Wallets:** 2% + GST

**No setup fees. No annual fees. Pay only for successful transactions.**

---

## 🔗 USEFUL LINKS

- **Dashboard:** https://dashboard.razorpay.com
- **Documentation:** https://razorpay.com/docs/
- **Test Cards:** https://razorpay.com/docs/payments/payments/test-card-details/
- **Support:** https://razorpay.com/support/
- **API Reference:** https://razorpay.com/docs/api/

---

## 📞 NEED HELP?

**Razorpay Support:**
- Email: support@razorpay.com
- Phone: 1800-102-0555 (India)
- Chat: Available on dashboard

**Common Questions:**
- KYC approval time: 1-2 business days
- Settlement time: T+2 to T+7 days
- Refund processing: Instant to 5-7 days

---

## ✅ CURRENT STATUS

- [x] Razorpay SDK installed
- [x] Backend routes created
- [x] Frontend integrated
- [x] `.env` file updated with placeholders
- [ ] **→ GET YOUR API KEYS NOW** ← (You are here)
- [ ] Test payment
- [ ] Complete KYC
- [ ] Go live

---

## 🚀 YOU'RE ALMOST THERE!

Just get your API keys from Razorpay dashboard and add them to `.env` file.

Then test a payment and you're done! 🎉
