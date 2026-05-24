const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");
const usersController = require("../../controllers/mobile/users.controller");

router.get("/profile", authenticateToken, usersController.getProfile);
router.put("/profile", authenticateToken, usersController.updateProfile);

router.post(
  "/save-fcm-token",
  authenticateToken,
  usersController.saveFcmToken
);


router.get(
  "/test-notification",
  authenticateToken,
  usersController.testNotification
);

module.exports = router;
