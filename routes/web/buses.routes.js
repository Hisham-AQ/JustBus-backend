const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");
const allowRoles = require("../../middleware/roleMiddleware");
const busesController = require("../../controllers/web/buses.controller");

// GET
router.get("/", busesController.getBuses);

// CREATE
router.post("/", authenticateToken, allowRoles("admin"), busesController.createBus);

// UPDATE
router.put("/:id", authenticateToken, allowRoles("admin"), busesController.updateBus);

// DELETE
router.delete("/:id", authenticateToken, allowRoles("admin"), busesController.deleteBus);

// OPTIONAL
router.get("/locations", authenticateToken, allowRoles("admin"), busesController.getBusLocations);

module.exports = router;