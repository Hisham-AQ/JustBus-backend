const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");

const controller = require("../../controllers/mobile/activity.controller");

router.get(
    "/",
    authenticateToken,
    controller.getMyActivity
);

router.post(
  "/request-cancellation",
  authMiddleware,
  requestCancellation
);


module.exports = router;