const express = require("express");

const router = express.Router();

const lostItemController =
  require("../../controllers/web/adminLostItem.controller");

const auth =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");


// ADMIN
router.get(
  "/admin/lost-items",
  auth,
  adminOnly,
  lostItemController.getAllReports
);

router.put(
  "/admin/lost-items/:id",
  auth,
  adminOnly,
  lostItemController.updateReportStatus
);

module.exports = router;