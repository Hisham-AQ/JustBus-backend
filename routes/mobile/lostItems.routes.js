const express = require("express");
const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const controller = require("../controllers/lostItems.controller");

router.post("/lost-items", authMiddleware, controller.createReport);
router.get("/lost-items/my", authMiddleware, controller.getMyReports);

module.exports = router;