const express = require("express");
const router = express.Router();

const {register,login,profile} = require("../controllers/authController");

const jwtMiddleware = require("../middleware/jwtMiddleware");

router.post("/register", register);
router.post("/login", login);
router.get("/profile", jwtMiddleware, profile);  //Protected profile route. Middleware runs before profile controller.

module.exports = router;