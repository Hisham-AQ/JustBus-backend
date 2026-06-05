const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller = require(
  "../../controllers/web/adminPoints.controller"
);

router.post(
  "/add",
  authenticateToken,
  adminOnly,
  controller.addPoints
);

router.post(
  "/remove",
  authenticateToken,
  adminOnly,
  controller.removePoints
);

router.get(
  "/history/:id",
  authenticateToken,
  adminOnly,
  controller.getPointsHistory
);

module.exports = router;