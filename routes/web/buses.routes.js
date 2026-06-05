const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");
const allowRoles = require("../../middleware/roleMiddleware");
const busesController = require("../../controllers/web/buses.controller");

router.get("/", busesController.getBuses);


router.post("/", authenticateToken, allowRoles("admin"), busesController.createBus);

router.put("/:id", authenticateToken, allowRoles("admin"), busesController.updateBus);

router.delete("/:id", authenticateToken, allowRoles("admin"), busesController.deleteBus);

router.get("/locations", authenticateToken, allowRoles("admin"), busesController.getBusLocations);

module.exports = router;