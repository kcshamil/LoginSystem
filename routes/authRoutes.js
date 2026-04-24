const express = require("express");
const router = express.Router();

const {register,login,profile,adminOnly, subadminOnly} = require("../controllers/authController");

const jwtMiddleware = require("../middleware/jwtMiddleware");

router.post("/register", register);
router.post("/login", login);
router.get("/profile", jwtMiddleware, profile);  //Protected profile route. Middleware runs before profile controller.
router.get("/admin", jwtMiddleware, adminOnly);
router.get("/subadmin",jwtMiddleware, subadminOnly)

module.exports = router;