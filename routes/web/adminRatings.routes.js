const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");
const allowRoles = require("../../middleware/roleMiddleware");
const ratingsController = require("../../controllers/mobile/userRatings.controller");

//  ANALYTICS
router.get("/analytics", authenticateToken, allowRoles("admin"), ratingsController.getAnalytics);

// COMMENTS
router.get("/comments", authenticateToken, allowRoles("admin"), ratingsController.getComments);

module.exports = router;