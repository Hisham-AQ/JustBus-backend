const express = require("express");
const router = express.Router();

const authMiddleware = require("../../middleware/authMiddleware");

const controller = require("../../controllers/mobile/lostItems.controller");

router.post(
  "/",
  authMiddleware,
  controller.createReport
);

router.get(
  "/my",
  authMiddleware,
  controller.getMyReports
);

module.exports = router;