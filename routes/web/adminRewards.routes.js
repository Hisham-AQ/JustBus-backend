const express = require("express");

const router = express.Router();

const controller = require(
  "../../controllers/web/adminRewards.controller"
);

// ================= REWARDS =================
router.get(
  "/",
  controller.getRewards
);

router.post(
  "/",
  controller.createReward
);

router.put(
  "/:id",
  controller.updateReward
);

router.delete(
  "/:id",
  controller.deleteReward
);

// ================= RULES =================
router.get(
  "/rules",
  controller.getRewardRules
);

router.put(
  "/rules",
  controller.updateRewardRules
);

module.exports = router;