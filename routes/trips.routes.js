const express = require("express");
const router = express.Router();

const tripsController = require("../controllers/trips.controller");

router.get("/cities", tripsController.getCities);
router.get("/trips", tripsController.searchTrips);
router.get("/trips/:tripId/seats", tripsController.getSeats);

module.exports = router;