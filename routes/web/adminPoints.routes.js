const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller = require(
  "../../controllers/web/adminPoints.controller"
);

// ================= ADD =================
router.post(
  "/add",
  authenticateToken,
  adminOnly,
  controller.addPoints
);

// ================= REMOVE =================
router.post(
  "/remove",
  authenticateToken,
  adminOnly,
  controller.removePoints
);

// ================= HISTORY =================
router.get(
  "/history/:id",
  authenticateToken,
  adminOnly,
  controller.getPointsHistory
);

module.exports = router;