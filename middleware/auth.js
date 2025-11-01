// middleware/authMiddleware.js

const jwt = require("jsonwebtoken");
const User = require("../models/user");

// ✅ Verify JWT Token (Protect Routes)
const protect = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ 
        success: false,
        message: "Unauthorized access. Please login again." 
      });
    }

    const token = authHeader.split(" ")[1];

    // Verify token
    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    } catch (err) {
      return res.status(401).json({
        success: false,
        message: "Session expired. Please login again."
      });
    }

    // ✅ Get User
    const user = await User.findById(payload.userId).select("-password");
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: "User not found. Please login again." 
      });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(500).json({ 
      success: false,
      message: "Authentication error" 
    });
  }
};

// ✅ Role-based Access Control
const authorize = (roles = []) => {
  if (typeof roles === "string") roles = [roles];

  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: "Please login first" });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        success: false,
        message: "Access denied. Admin only." 
      });
    }

    next();
  };
};

module.exports = { protect, authorize };
