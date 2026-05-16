const express = require("express");
const router = express.Router();
const aiController = require("../../controllers/mobile/ai.controller");

router.post("/ai/chat", aiController.chat);

module.exports = router;