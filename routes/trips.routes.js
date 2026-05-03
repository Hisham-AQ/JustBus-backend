const express = require("express");
const router = express.Router();

const tripsController = require("../controllers/trips.controller");
const authenticateToken = require("../middleware/authMiddleware"); 

router.get("/cities", tripsController.getCities);
router.get("/trips", tripsController.searchTrips);
router.get("/trips/:tripId/seats", tripsController.getSeats);

router.get("/my", authenticateToken, tripsController.getMyTrips);

module.exports = router;