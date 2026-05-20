const express =
  require("express");

const router =
  express.Router();

const controller =
  require("../../controllers/web/adminWallet.controller");

router.get(
  "/students",
  controller.getStudentWallets
);

router.put(
  "/students/:id/balance",
  controller.updateStudentBalance
);

module.exports =
  router;