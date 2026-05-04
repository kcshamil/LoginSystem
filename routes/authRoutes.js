const express = require("express");
const router = express.Router();

const {register,login,profile,adminOnly, subadminOnly, unlockAccount, requestUnlockOtp, verifyUnlockOtp} = require("../controllers/authController");

const jwtMiddleware = require("../middleware/jwtMiddleware");

router.post("/register", register);
router.post("/login", login);
router.get("/profile", jwtMiddleware, profile);  //Protected profile route. Middleware runs before profile controller.
router.get("/admin", jwtMiddleware, adminOnly);
router.get("/subadmin",jwtMiddleware, subadminOnly);
router.post("/admin/unlock-user", jwtMiddleware, unlockAccount);
router.post("/request-unlock-otp", requestUnlockOtp);
router.post("/verify-unlock-otp", verifyUnlockOtp);
module.exports = router;