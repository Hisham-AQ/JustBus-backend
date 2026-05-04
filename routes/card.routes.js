const express = require("express");
const router = express.Router();
const controller = require("../controllers/card.controller");
const authenticateToken = require("../middleware/authMiddleware");

router.get("/", authenticateToken, controller.getCards);
router.post("/", authenticateToken, controller.addCard);
router.delete("/:id", authenticateToken, controller.deleteCard);

module.exports = router;