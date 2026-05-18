const express = require("express");

const router = express.Router();

const controller = require(
  "../../controllers/web/adminRatings.controller"
);

router.get(
  "/analytics",
  controller.getAnalytics
);

router.get(
  "/comments",
  controller.getComments
);

router.get(
  "/drivers",
  controller.getDriverRatings
);

router.get(
  "/drivers/:id/reviews",
  controller.getDriverReviews
);

module.exports = router;