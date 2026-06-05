const express = require("express");
const router = express.Router();

const walletController = require("../../controllers/mobile/wallet.controller");
const authMiddleware = require("../../middleware/authMiddleware");


router.get("/", authMiddleware, walletController.getBalance);

router.post("/topup", authMiddleware, walletController.topUp);

router.post("/pay", authMiddleware, walletController.payWithWallet);

router.get("/transactions", authMiddleware, walletController.getTransactions);

module.exports = router;