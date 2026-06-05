const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");
const allowRoles = require("../../middleware/roleMiddleware");
const studentsController = require("../../controllers/web/students.controller");

router.get("/", authenticateToken, allowRoles("admin"), studentsController.getStudents);

router.get("/leaderboard", authenticateToken, allowRoles("admin"), studentsController.getLeaderboard);

router.post("/:id/blacklist", authenticateToken, allowRoles("admin"), studentsController.blacklistStudent);

router.post("/blacklist-manual", authenticateToken, allowRoles("admin"), studentsController.manualBlacklist);

router.delete("/:id/blacklist", authenticateToken, allowRoles("admin"), studentsController.removeBlacklist);

router.delete("/:id", authenticateToken, allowRoles("admin"), studentsController.deleteStudent);

module.exports = router;