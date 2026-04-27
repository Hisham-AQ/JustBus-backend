const express = require("express");
const router = express.Router();

const authenticateToken = require("../middleware/authMiddleware");
const bookingsController = require("../controllers/bookings.controller");

router.post("/bookings/hold", authenticateToken, bookingsController.holdSeats);
router.post("/bookings/confirm", authenticateToken, bookingsController.confirmBooking);

module.exports = router;