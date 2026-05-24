const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller = require(
  "../../controllers/web/adminTripBookings.controller"
);

// ================= GET ALL TRIP BOOKINGS =================
router.get(
  "/",
  authenticateToken,
  adminOnly,
  controller.getTripBookings
);

// ================= GET PASSENGERS =================
router.get(
  "/:id/passengers",
  authenticateToken,
  adminOnly,
  controller.getTripPassengers
);

router.put(
  "/cancel/:bookingId",
  authenticateToken,
  adminOnly,
  controller.cancelBooking
);

module.exports = router;
