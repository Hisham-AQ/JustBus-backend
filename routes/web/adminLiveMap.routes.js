const express =
  require("express");

const router =
  express.Router();

const controller =
  require("../../controllers/web/adminLiveMap.controller");

router.get(
  "/live-buses",
  controller.getLiveBuses
);

module.exports =
  router;