const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");
const allowRoles = require("../../middleware/roleMiddleware");
const adminTrips = require("../../controllers/web/adminTrips.controller"); 

router.get("/", authenticateToken, allowRoles("admin"), adminTrips.getTrips);

router.post("/", authenticateToken, allowRoles("admin"), adminTrips.createTrip);

router.put("/:id", authenticateToken, allowRoles("admin"), adminTrips.updateTrip);

router.delete("/:id", authenticateToken, allowRoles("admin"), adminTrips.deleteTrip);

module.exports = router;