const express = require("express");

const router = express.Router();

const controller =
  require("../../controllers/web/adminParcels.controller");

router.get('/notifications/count', controller.getParcelNotifications);

router.get("/", controller.getParcels);

router.patch("/:id/status", controller.updateParcelStatus);

router.delete("/:id", controller.deleteParcel);

router.patch(
  "/:id/verify-delivery",
  controller.verifyDelivery
);



module.exports = router;