const express = require("express");
const router = express.Router();

const controller = require("../controllers/wallet.controller");
const authenticateToken = require("../middleware/authMiddleware");
const authMiddleware = require("../middleware/authMiddleware");

router.get("/", authenticateToken, controller.getBalance);
router.post("/topup", authenticateToken, controller.topUp);
router.post("/pay", authMiddleware, walletController.payWithWallet);
router.get("/transactions", authMiddleware, walletController.getTransactions);

module.exports = router;