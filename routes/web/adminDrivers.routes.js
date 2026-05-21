const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller =
  require("../../controllers/web/adminDrivers.controller");

// Driver activity
router.get(
  "/activity",
  authenticateToken,
  adminOnly,
  controller.getDriverActivity
);

// Get all drivers
router.get(
  "/",
  authenticateToken,
  adminOnly,
  controller.getDrivers
);

// Create
router.post(
  "/",
  authenticateToken,
  adminOnly,
  controller.createDriver
);

// Update
router.put(
  "/:id",
  authenticateToken,
  adminOnly,
  controller.updateDriver
);

// Delete
router.delete(
  "/:id",
  authenticateToken,
  adminOnly,
  controller.deleteDriver
);

module.exports = router;