const express = require("express");
const router = express.Router();

const controller = require("../controllers/wallet.controller");
const authenticateToken = require("../middleware/authMiddleware");

router.get("/", authenticateToken, controller.getBalance);
router.post("/topup", authenticateToken, controller.topUp);

module.exports = router;