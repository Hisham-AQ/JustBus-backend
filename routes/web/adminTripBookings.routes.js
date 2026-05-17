const express = require("express");

const router = express.Router();

const controller = require(
  "../../controllers/web/adminTripBookings.controller"
);

// ================= GET ALL TRIP BOOKINGS =================
router.get(
  "/",
  controller.getTripBookings
);

// ================= GET PASSENGERS =================
router.get(
  "/:id/passengers",
  controller.getTripPassengers
);

module.exports = router;