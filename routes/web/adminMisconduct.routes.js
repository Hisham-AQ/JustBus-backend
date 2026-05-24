const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller =
  require("../../controllers/web/adminMisconduct.controller");

// Get reports
router.get(
  "/",
  authenticateToken,
  adminOnly,
  controller.getReports
);

// Resolve
router.put(
  "/resolve/:id",
  authenticateToken,
  adminOnly,
  controller.resolveReport
);

// Blacklist
router.put(
  "/blacklist/:userId",
  authenticateToken,
  adminOnly,
  controller.blacklistStudent
);

module.exports = router;