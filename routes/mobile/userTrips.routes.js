const express = require("express");
const router = express.Router();

const tripsController = require("../../controllers/mobile/userTrips.controller");

const authenticateToken = require("../../middleware/authMiddleware");

router.get("/cities", tripsController.getCities);

router.get("/", tripsController.searchTrips);

router.get("/my", authenticateToken, tripsController.getMyTrips);

router.get("/:tripId/seats", tripsController.getSeats);

router.get("/live-location/:tripId", authenticateToken, tripsController.getLiveLocation);

module.exports = router;