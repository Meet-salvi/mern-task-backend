const express = require('express');
const cors = require('cors');
const connectDb = require('./Db/connectDb');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const { protect } = require('./middleware/auth');
const productRoutes = require('./routes/productRoutes');

const app = express();
const PORT = process.env.PORT || 8000;

// ✅ Allowed frontend URLs
const allowedOrigins = process.env.CLIENT_URL.split(",");

// ✅ CORS Middleware
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // ✅ Handle browser preflight
  if (req.method === "OPTIONS") return res.sendStatus(200);

  next();
});

// ✅ Security Middlewares
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ✅ Rate Limiter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { message: "Too many requests, try again later." }
});

// ✅ Routes
app.use("/api/auth", authLimiter, authRoutes);
app.use("/api/products", productRoutes);

// ✅ Protected test route
app.get("/api/dashboard", protect, (req, res) => {
  res.json({
    message: `Welcome, user with ID ${req.user.id}`,
    role: req.user.role
  });
});

// ✅ Root test route
app.get("/", (req, res) => {
  res.json({ message: "Server running ✅" });
});

// ✅ Start Server
app.listen(PORT, () => {
  connectDb();
  console.log(`✅ Server running on port ${PORT}`);
});
