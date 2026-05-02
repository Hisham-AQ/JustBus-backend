const express = require("express");
const router = express.Router();

const authenticateToken = require("../middleware/authMiddleware");
const allowRoles = require("../middleware/roleMiddleware");
const usersController = require("../controllers/users.controller");

// GET users
router.get(
  "/users",
  authenticateToken,
  allowRoles("admin"),
  usersController.getUsers
);

module.exports = router;