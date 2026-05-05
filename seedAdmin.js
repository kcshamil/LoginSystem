require("dotenv").config();
const db = require("./config/db");
const bcrypt = require("bcryptjs");

const seedAdmin = async () => {
  const name = "Master Admin";
  const email = "admin@mnc.com";
  const password = "AdminPassword123!"; // Change this after login
  const role = "admin";

  try {
    console.log("Checking if Admin already exists...");
    const [rows] = await db.query("SELECT * FROM admins WHERE email = ?", [email]);

    if (rows.length > 0) {
      console.log("Admin already exists. No seeding needed.");
      process.exit(0);
    }

    console.log("Hashing password...");
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    console.log("Creating Master Admin...");
    await db.query(
      "INSERT INTO admins (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword]
    );

    console.log("Success: Master Admin created successfully!");
    console.log(`Email: ${email}`);
    console.log(`Password: ${password}`);
    process.exit(0);
  } catch (error) {
    console.error("Error seeding admin:", error.message);
    process.exit(1);
  }
};

seedAdmin();
