const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");

const bookingsController = require("../../controllers/mobile/bookings.controller");

router.post(
  "/hold",
  authenticateToken,
  bookingsController.holdSeats
);

router.post(
  "/confirm",
  authenticateToken,
  bookingsController.confirmBooking
);

module.exports = router;