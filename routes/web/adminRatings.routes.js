const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller = require(
  "../../controllers/web/adminRatings.controller"
);

router.get(
  "/analytics",
  authenticateToken,
  adminOnly,
  controller.getAnalytics
);

router.get(
  "/comments",
  authenticateToken,
  adminOnly,
  controller.getComments
);

router.get(
  "/drivers",
  authenticateToken,
  adminOnly,
  controller.getDriverRatings
);

router.get(
  "/drivers/:id/reviews",
  authenticateToken,
  adminOnly,
  controller.getDriverReviews
);

module.exports = router;