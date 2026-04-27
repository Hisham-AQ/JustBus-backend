const express = require("express");
const router = express.Router();

const authenticateToken = require("../middleware/authMiddleware");
const userController = require("../controllers/user.controller");

router.get("/profile", authenticateToken, userController.getProfile);
router.put("/profile", authenticateToken, userController.updateProfile);

module.exports = router;