const express = require("express");
const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const panicController =
  require("../../controllers/mobile/panic.controller");

router.post(
  "/",
  authenticateToken,
  panicController.sendPanicAlert
);

module.exports = router;