const express = require("express");
const router = express.Router();

const authenticateToken = require("../middleware/authMiddleware");
const allowRoles = require("../middleware/roleMiddleware");
const studentsController = require("../controllers/students.controller");

// GET students
router.get("/", authenticateToken, allowRoles("admin"), studentsController.getStudents);

// leaderboard
router.get("/leaderboard", authenticateToken, allowRoles("admin"), studentsController.getLeaderboard);

// blacklist student
router.post("/:id/blacklist", authenticateToken, allowRoles("admin"), studentsController.blacklistStudent);

// manual blacklist
router.post("/blacklist-manual", authenticateToken, allowRoles("admin"), studentsController.manualBlacklist);

// remove blacklist
router.delete("/:id/blacklist", authenticateToken, allowRoles("admin"), studentsController.removeBlacklist);

// delete student
router.delete("/:id", authenticateToken, allowRoles("admin"), studentsController.deleteStudent);

module.exports = router;