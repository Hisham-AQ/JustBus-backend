const express = require("express");
const router = express.Router();
const controller = require("../../controllers/mobile/userCard.controller");
const authenticateToken = require("../../middleware/authMiddleware");

router.get("/", authenticateToken, controller.getCards);
router.post("/", authenticateToken, controller.addCard);
router.delete("/:id", authenticateToken, controller.deleteCard);

module.exports = router;