const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");
const allowRoles = require("../../middleware/roleMiddleware");

const driversController = require("../../controllers/web/adminDrivers.controller");

// GET all drivers
router.get("/", authenticateToken, allowRoles("admin"), driversController.getDrivers);

// CREATE driver
router.post("/", authenticateToken, allowRoles("admin"), driversController.createDriver);

// UPDATE driver
router.put("/:id", authenticateToken, allowRoles("admin"), driversController.updateDriver);

// DELETE driver
router.delete("/:id", authenticateToken, allowRoles("admin"), driversController.deleteDriver);

module.exports = router;