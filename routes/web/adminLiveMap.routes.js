const express =
  require("express");

const router =
  express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller =
  require("../../controllers/web/adminLiveMap.controller");

router.get(
  "/live-buses",
  authenticateToken,
  adminOnly,
  controller.getLiveBuses
);

module.exports =
  router;