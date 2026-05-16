const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");
const specialTripsController = require("../../controllers/mobile/specialTrips.controller");

router.get("/special-trips", specialTripsController.getAllSpecialTrips);
router.get("/special-trips/:id", specialTripsController.getSpecialTrip);
router.post("/special-trips/book", authenticateToken, specialTripsController.bookSpecialTrip);

module.exports = router;