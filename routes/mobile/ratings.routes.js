const express = require("express");

const router = express.Router();

const ratingsController = require("../../controllers/mobile/ratings.controller");

const authMiddleware = require("../../middleware/authMiddleware");

router.post("/", authMiddleware, ratingsController.submitRating);

module.exports = router;