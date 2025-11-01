// middleware/authMiddleware.js

const jwt = require("jsonwebtoken");
const User = require("../models/user");

const protect = async (req, res, next) => {
  try {
    let token;

    // ✅ Get token from Authorization header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    }

    // ✅ Fallback: token from cookie
    if (!token && req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized access. Please login again.",
      });
    }

    // ✅ Verify token
    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    } catch (err) {
      return res.status(401).json({
        success: false,
        message: "Session expired. Please login again.",
      });
    }

    // ✅ Get user
    const user = await User.findById(payload.userId).select("-password");
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found. Please login again.",
      });
    }

    req.user = user;
    next();
  } catch (err) {
    console.log("Auth error:", err);
    return res.status(500).json({
      success: false,
      message: "Authentication error",
    });
  }
};

// ✅ Role-Based Access
const authorize = (roles = []) => {
  if (typeof roles === "string") roles = [roles];

  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: "Please login first" });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: "Access denied. Admin only.",
      });
    }

    next();
  };
};

module.exports = { protect, authorize };
