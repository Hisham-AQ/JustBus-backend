const express = require("express");
const router = express.Router();

const authenticateToken = require("../middleware/authMiddleware");
const allowRoles = require("../middleware/roleMiddleware");
const driversController = require("../controllers/drivers.controller");

// GET
router.get("/", authenticateToken, allowRoles("admin"), driversController.getDrivers);

// CREATE
router.post("/", authenticateToken, allowRoles("admin"), driversController.createDriver);

// UPDATE
router.put("/:id", authenticateToken, allowRoles("admin"), driversController.updateDriver);

// DELETE
router.delete("/:id", authenticateToken, allowRoles("admin"), driversController.deleteDriver);

module.exports = router;