const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");

const parcelsController = require("../../controllers/mobile/parcels.controller");

console.log("Controller:", parcelsController);

// ================= GET PARCELS =================
router.get(
  "/parcels",
  authenticateToken,
  parcelsController.getParcels
);

// ================= CREATE PARCEL =================
router.post(
  "/parcels",
  authenticateToken,
  parcelsController.createParcel
);

// ================= UPDATE STATUS =================
router.patch(
  "/parcels/:id/status",
  authenticateToken,
  parcelsController.updateParcelStatus
);

module.exports = router;