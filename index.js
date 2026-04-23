require("dotenv").config();

const express = require("express");
const cors = require("cors");
const authRoutes = require("./routes/authRoutes");

const app = express();

app.use(cors());  //Allows frontend to access backend.
app.use(express.json());  //Converts JSON request body into JavaScript object.

app.use("/api/auth", authRoutes);

app.get("/", (req, res) => {
  res.send("<h1>Login system API is running</h1>");
});

app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});