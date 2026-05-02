const express = require("express");
const router = express.Router();

const authenticateToken = require("../middleware/authMiddleware");
const allowRoles = require("../middleware/roleMiddleware");
const routesController = require("../controllers/routes.controller");

// GET
router.get("/", authenticateToken, allowRoles("admin"), routesController.getRoutes);

// CREATE
router.post("/", authenticateToken, allowRoles("admin"), routesController.createRoute);

// UPDATE
router.put("/:id", authenticateToken, allowRoles("admin"), routesController.updateRoute);

// DELETE
router.delete("/:id", authenticateToken, allowRoles("admin"), routesController.deleteRoute);

module.exports = router;