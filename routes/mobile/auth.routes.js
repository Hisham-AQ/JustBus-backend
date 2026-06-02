const express = require("express");
const router = express.Router();
const rateLimit = require("express-rate-limit");
const { body } = require("express-validator");

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, //block for 15 minute
  max: 10,  //each ip has 10 attemps
  message: {
    message: "Too many login attempts. Try again later."
  }
});

const authenticateToken = require("../../middleware/authMiddleware");
const authController = require("../../controllers/mobile/auth.controller");


router.post(
  "/login",
  loginLimiter,
  [
    body("email")
      .isEmail()
      .withMessage("Invalid email"),

    body("password")
      .notEmpty()
      .withMessage("Password is required")
  ],
  authController.login
);

router.post("/admin/login", loginLimiter,
  [
    body("email")
      .isEmail()
      .withMessage("Invalid email"),

    body("password")
      .notEmpty()
      .withMessage("Password is required")
  ],
  authController.adminLogin
);

router.post(
  "/register",
  [
    body("name")
      .trim()
      .isLength({ min: 2 })
      .withMessage("Name must be at least 2 characters"),

    body("email")
      .isEmail()
      .withMessage("Invalid email"),

    body("password")
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/)
      .withMessage(
        "Password must be at least 8 characters and contain uppercase, lowercase, and a number"
      ),

    body("phone")
      .matches(/^\d{9,15}$/)
      .withMessage("Invalid phone number")
  ],
  authController.register
);

router.put("/change-password", authenticateToken, authController.changePassword);
router.post("/forgot-password", authController.forgotPassword);
router.post("/reset-password", authController.resetPassword);

module.exports = router;