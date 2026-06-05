const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller =
  require("../../controllers/web/adminDrivers.controller");

router.get(
  "/activity",
  authenticateToken,
  adminOnly,
  controller.getDriverActivity
);

router.get(
  "/",
  authenticateToken,
  adminOnly,
  controller.getDrivers
);

router.post(
  "/",
  authenticateToken,
  adminOnly,
  controller.createDriver
);

router.put(
  "/:id",
  authenticateToken,
  adminOnly,
  controller.updateDriver
);

router.delete(
  "/:id",
  authenticateToken,
  adminOnly,
  controller.deleteDriver
);

module.exports = router;