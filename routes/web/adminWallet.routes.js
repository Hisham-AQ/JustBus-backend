const express =
  require("express");

const router =
  express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller =
  require("../../controllers/web/adminWallet.controller");

router.get(
  "/students",
  authenticateToken,
  adminOnly,
  controller.getStudentWallets
);

router.put(
  "/students/:id/balance",
  authenticateToken,
  adminOnly,
  controller.updateStudentBalance
);

module.exports =
  router;