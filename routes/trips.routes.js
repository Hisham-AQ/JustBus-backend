const express = require("express");
const router = express.Router();

const tripsController = require("../controllers/trips.controller");
const authenticateToken = require("../middleware/authMiddleware");
const controller = require("../controllers/trips.controller");


router.get("/cities", tripsController.getCities);
router.get("/trips", tripsController.searchTrips);
router.get("/my", authenticateToken, tripsController.getMyTrips);
router.get("/trips/:tripId/seats", tripsController.getSeats);
router.get("/live-location/:tripId",controller.getLiveLocation);

module.exports = router;