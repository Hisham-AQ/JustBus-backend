const express = require("express");
const router = express.Router();

const authenticateToken = require("../middleware/authMiddleware");
const usersController = require("../controllers/users.controller");

router.get("/profile", authenticateToken, usersController.getProfile);
router.put("/profile", authenticateToken, usersController.updateProfile);

module.exports = router;