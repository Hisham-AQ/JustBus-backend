const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");
const allowRoles = require("../../middleware/roleMiddleware");
const adminTrips = require("../../controllers/web/adminTrips.controller"); 

// GET all trips
router.get("/", authenticateToken, allowRoles("admin"), adminTrips.getTrips);

// CREATE trip
router.post("/", authenticateToken, allowRoles("admin"), adminTrips.createTrip);

// UPDATE trip
router.put("/:id", authenticateToken, allowRoles("admin"), adminTrips.updateTrip);

// DELETE trip
router.delete("/:id", authenticateToken, allowRoles("admin"), adminTrips.deleteTrip);

module.exports = router;