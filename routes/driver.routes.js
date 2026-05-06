const express = require("express");
const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const controller = require("../controllers/driver.controller");

router.get(
    "/current-trip",
    authMiddleware,
    controller.getCurrentTrip
);

module.exports = router;


router.patch(
    "/start-trip",
    authMiddleware,
    controller.startTrip
);

router.patch(
    "/end-trip",
    authMiddleware,
    controller.endTrip
);

router.post(
    "/scan-ticket",
    authMiddleware,
    controller.scanTicket
);

router.get(
    "/passengers",
    authMiddleware,
    controller.getPassengers
);

router.patch(
    "/dropoff",
    authMiddleware,
    controller.dropOffPassenger
);

router.post(
  "/report-misconduct",
  authMiddleware,
  controller.reportMisconduct
);