const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");

const parcelsController = require("../../controllers/mobile/parcels.controller");

// ================= GET PARCELS =================
router.get(
  "/",
  authenticateToken,
  parcelsController.getParcels
);

// ================= CREATE PARCEL =================
router.post(
  "/",
  authenticateToken,
  parcelsController.createParcel
);

// ================= UPDATE STATUS =================
router.patch(
  "/:id/status",
  authenticateToken,
  parcelsController.updateParcelStatus
);

module.exports = router;