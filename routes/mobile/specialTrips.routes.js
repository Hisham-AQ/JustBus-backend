const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");

const specialTripsController = require("../../controllers/mobile/specialTrips.controller");

router.get("/", specialTripsController.getAllSpecialTrips);

router.get("/:id", specialTripsController.getSpecialTrip);

router.post(
    "/book",
    authenticateToken,
    specialTripsController.bookSpecialTrip
);

module.exports = router;