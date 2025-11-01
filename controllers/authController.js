// controllers/authController.js
const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/user');

const ms = (str) => { // helper parse - very simple
  // You can use "ms" npm package — here we rely on jwt option strings from env.
  return undefined;
};

const signAccessToken = (user) => {
  return jwt.sign(
    { userId: user._id.toString(), role: user.role },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || '2h' }
  );
};

const signRefreshToken = (user) => {
  return jwt.sign(
    { userId: user._id.toString() },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '30d' }
  );
};

const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production", // HTTPS only in production
  sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
};

exports.register = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const { name, email, password } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ message: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ name, email, password: hashed });

    // tokens
    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);

    user.refreshTokenHash = hashToken(refreshToken);
    await user.save();

    // send refresh token as HttpOnly cookie
    res.cookie('refreshToken', refreshToken, {
      ...cookieOptions,
      maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days (match REFRESH_TOKEN_EXPIRES_IN)
    });

    return res.status(201).json({
      message: 'Registered',
      accessToken,
      user: { id: user._id, name: user.name, email: user.email }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
};


exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(422).json({ message: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid email" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid password" });

    const accessToken = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: "15m" }
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    // Save refresh token in DB
    user.refreshTokenHash = refreshToken;
    await user.save();

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({
      message: "Login successful",
      accessToken,
      user: { id: user._id, name: user.name, email: user.email },
    });

  } catch (err) {
    console.error("LOGIN ERROR =>", err);
    return res.status(500).json({ message: "Server error" });
  }
};


exports.refreshToken = async (req, res) => {
  try {
    const token = req.cookies.refreshToken || req.body.refreshToken;
    if (!token) return res.status(401).json({ message: 'No refresh token' });

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    } catch (e) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    const tokenHash = hashToken(token);
    const user = await User.findOne({ _id: payload.userId, refreshTokenHash: tokenHash });
    if (!user) return res.status(401).json({ message: 'Refresh token not recognized' });

    // rotate: new refresh token & access token
    const newAccessToken = signAccessToken(user);
    const newRefreshToken = signRefreshToken(user);
    user.refreshTokenHash = hashToken(newRefreshToken);
    await user.save();

    res.cookie('refreshToken', newRefreshToken, {
      ...cookieOptions,
      maxAge: 1000 * 60 * 60 * 24 * 7
    });

    return res.json({
      accessToken: newAccessToken,
      user: { id: user._id, name: user.name, email: user.email }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
};


exports.logout = async (req, res) => {
  try {
    const token = req.cookies.refreshToken || req.body.refreshToken;
    if (token) {
      // remove hashed refresh token from DB (logout everywhere for this user if you want)
      try {
        const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
        await User.findByIdAndUpdate(payload.userId, { $set: { refreshTokenHash: null } });
      } catch (e) {
        // ignore invalid token
      }
    }

    res.clearCookie('refreshToken', cookieOptions);
    return res.json({ message: 'Logged out' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
};



