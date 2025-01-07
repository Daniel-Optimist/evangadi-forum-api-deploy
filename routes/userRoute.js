const express = require("express");
const router = express.Router();

// Authentication middleware
const authMiddleware = require("../middleware/authMiddleware");

// User controller
const {
  register,
  login,
  check,
  requestPasswordReset,
  resetPassword,
  validateResetToken, // Added validateResetToken controller method
} = require("../controller/userController");

// User registration route
router.post("/register", register);

// User login route
router.post("/login", login);

// Check user route
router.get("/checkUser", authMiddleware, check);

// Password reset request route (Step 1: Requesting password reset)
router.post("/requestPasswordReset", requestPasswordReset);

// Password reset route (Step 2: Resetting the password using the token)
router.post("/resetPassword/:token", resetPassword);  // patch used since we are updating a password of an existing user

// Validate reset token route (Step 5: Validating the reset token)
router.post("/validateResetToken", validateResetToken); // New route for token validation

module.exports = router;
