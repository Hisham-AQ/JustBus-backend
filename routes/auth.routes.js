const express = require("express");
const router = express.Router();

const authenticateToken = require("../middleware/authMiddleware");
const authController = require("../controllers/auth.controller");

router.post("/register", authController.register);
router.post("/login", authController.login);
////test only
console.log(authController);
//////////
router.post("/admin/login", authController.adminLogin);

router.put("/change-password", authenticateToken, authController.changePassword);
router.post("/forgot-password", authController.forgotPassword);
router.post("/reset-password", authController.resetPassword);

module.exports = router;