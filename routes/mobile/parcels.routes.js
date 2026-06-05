const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");

const parcelsController = require("../../controllers/mobile/parcels.controller");

router.get(
  "/",
  authenticateToken,
  parcelsController.getParcels
);

router.post(
  "/",
  authenticateToken,
  parcelsController.createParcel
);

router.patch(
  "/:id/status",
  authenticateToken,
  parcelsController.updateParcelStatus
);

module.exports = router;