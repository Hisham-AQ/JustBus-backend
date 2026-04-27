const express = require("express");
const router = express.Router();

const authenticateToken = require("../middleware/authMiddleware");
const parcelsController = require("../controllers/parcels.controller");

router.post("/parcels", authenticateToken, parcelsController.createParcel);

module.exports = router;