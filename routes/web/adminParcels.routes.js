const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller =
  require("../../controllers/web/adminParcels.controller");

router.get(
  "/notifications/count",
  authenticateToken,
  adminOnly,
  controller.getParcelNotifications
);

router.get(
  "/",
  authenticateToken,
  adminOnly,
  controller.getParcels
);

router.patch(
  "/:id/status",
  authenticateToken,
  adminOnly,
  controller.updateParcelStatus
);

router.delete(
  "/:id",
  authenticateToken,
  adminOnly,
  controller.deleteParcel
);

router.patch(
  "/:id/verify-delivery",
  authenticateToken,
  adminOnly,
  controller.verifyDelivery
);

module.exports = router;