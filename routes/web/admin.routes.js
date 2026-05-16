const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");

const usersController = require("../../controllers/mobile/users.controller");

// GET users
router.get(
  "/users",
  authenticateToken,
  usersController.getUsers
);

module.exports = router;