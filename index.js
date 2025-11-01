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
const PORT = process.env.PORT;

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Allow cookies/token to be sent with requests
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

// ✅ Rate limiter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { message: 'Too many requests, try again later.' }
});

// ✅ Routes
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/products', productRoutes);

// ✅ Protected route
app.get('/api/dashboard', protect, (req, res) => {
  res.json({
    message: `Welcome, user with ID ${req.user.id}`,
    role: req.user.role
  });
});

app.get('/', async (req, res) => {
  res.json({ Message: "Success" });
});

app.listen(PORT, () => {
  connectDb();
  console.log("✅ Server Started on port:", PORT);
});
