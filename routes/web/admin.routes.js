const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");
const adminOnly = require("../../middleware/adminOnly");

const usersController = require("../../controllers/mobile/users.controller");

// GET users
router.get(
  "/users",
  authenticateToken,
  adminOnly,
  usersController.getUsers
);

module.exports = router;