const express = require("express");

const router = express.Router();

const controller = require("../../controllers/web/adminSpecialTrips.controller");

router.get("/", controller.getSpecialTrips);

router.post("/", controller.createSpecialTrip);

router.put("/:id", controller.updateSpecialTrip);

router.delete("/:id", controller.deleteSpecialTrip);

module.exports = router;