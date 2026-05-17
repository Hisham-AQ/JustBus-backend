const express = require("express");

const router = express.Router();

const controller = require(
  "../../controllers/web/adminPoints.controller"
);

// ================= ADD =================
router.post(
  "/add",
  controller.addPoints
);

// ================= REMOVE =================
router.post(
  "/remove",
  controller.removePoints
);

// ================= HISTORY =================
router.get(
  "/history/:id",
  controller.getPointsHistory
);

module.exports = router;