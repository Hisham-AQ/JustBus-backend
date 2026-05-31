const express = require("express");

const router = express.Router();

const authenticateToken =
require("../../middleware/authMiddleware");

const adminOnly =
require("../../middleware/adminOnly");

const controller =
require("../../controllers/web/adminCancellationRequests.controller");

router.get(
  "/",
  authenticateToken,
  adminOnly,
  controller.getCancellationRequests
);

router.put(
  "/:id/approve",
  authenticateToken,
  adminOnly,
  controller.approveRequest
);

router.put(
  "/:id/reject",
  authenticateToken,
  adminOnly,
  controller.rejectRequest
);


module.exports = router;