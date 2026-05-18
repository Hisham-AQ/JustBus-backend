const express = require("express");

const router = express.Router();

const controller =
  require("../../controllers/web/adminDrivers.controller");

// Driver activity
router.get(
  "/activity",
  controller.getDriverActivity
);

// Get all drivers
router.get(
  "/",
  controller.getDrivers
);

// Create
router.post(
  "/",
  controller.createDriver
);

// Update
router.put(
  "/:id",
  controller.updateDriver
);

// Delete
router.delete(
  "/:id",
  controller.deleteDriver
);

module.exports = router;