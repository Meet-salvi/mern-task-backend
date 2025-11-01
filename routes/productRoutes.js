// routes/productRoutes.js
const express = require("express");
const router = express.Router();

const {
  createProduct,
  getProducts,
  getProductBySlug,
  updateProduct,
  deleteProduct
} = require("../controllers/productController");

// ✅ Only protect middleware now
const { protect } = require("../middleware/auth");

// Public routes
router.get("/", getProducts);
router.get("/:slug", getProductBySlug);

// ✅ Authenticated user can manage products
router.post("/", protect, createProduct);
router.put("/:slug", protect, updateProduct);
router.delete("/:slug", protect, deleteProduct);

module.exports = router;
