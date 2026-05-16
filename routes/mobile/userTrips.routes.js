const express = require("express");
const router = express.Router();

const tripsController = require("../../controllers/mobile/userTrips.controller");
const authenticateToken = require("../../middleware/authMiddleware");
const controller = require("../../controllers/mobile/userTrips.controller");
const authMiddleware = require("../../middleware/authMiddleware");


router.get("/cities", tripsController.getCities);
router.get("/trips", tripsController.searchTrips);
router.get("/my", authenticateToken, tripsController.getMyTrips);
router.get("/trips/:tripId/seats", tripsController.getSeats);
router.get("/live-location/:tripId", authMiddleware, tripsController.getLiveLocation);

module.exports = router;