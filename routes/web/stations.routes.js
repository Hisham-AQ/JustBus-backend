const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");
const allowRoles = require("../../middleware/roleMiddleware");

const stationsController = require("../../controllers/web/stations.controller");

router.get("/", authenticateToken, allowRoles("admin"), stationsController.getStations);

module.exports = router;