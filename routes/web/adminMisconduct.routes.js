const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller =
  require("../../controllers/web/adminMisconduct.controller");

router.get(
  "/",
  authenticateToken,
  adminOnly,
  controller.getReports
);

router.put(
  "/resolve/:id",
  authenticateToken,
  adminOnly,
  controller.resolveReport
);

router.put(
  "/blacklist/:userId",
  authenticateToken,
  adminOnly,
  controller.blacklistStudent
);

module.exports = router;