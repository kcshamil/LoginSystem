const db = require("../config/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const transporter = require("../config/mailer");

const getTableByRole = (role) => {  //Creates helper function to identify table from role.
  if (role === "public") return "public_users";
  if (role === "subadmin") return "sub_admins";
  if (role === "admin") return "admins";
  return null;
};   //Returns correct table name.If role is invalid, returns null.


const register = async (req, res) => {  //Creates async register function.
  try {
    const { name, email, password, role } = req.body;  //Gets name, email, password, and role from request body.

    if (!name || !email || !password || !role) {
      return res.status(400).json({ message: "All fields are required" });
    }  //Checks that no field is empty.

    const table = getTableByRole(role);  //Finds which table to use.

    if (!table) {
      return res.status(400).json({ message: "Invalid role" });
    }  //If role is not valid, return error.

    const [existingUsers] = await db.query(
      `SELECT * FROM ${table} WHERE email = ?`,
      [email]
    );  //Checks whether email already exists in that role table.(? is placeholder to prevent SQL injection.)

    if (existingUsers.length > 0) {
      return res.status(409).json({ message: "User already exists" });
    }  //If user exists, return conflict error.

    const salt = await bcrypt.genSalt(10);   //Creates salt with 10 rounds.
    const hashedPassword = await bcrypt.hash(password, salt);  //Hashes password with salt.

    const [result] = await db.query(
      `INSERT INTO ${table} (name, email, password) VALUES (?, ?, ?)`,
      [name, email, hashedPassword]
    );  //Inserts user into correct table.

    await transporter.sendMail({
      from: process.env.MAIL_USER,
      to: email,
      subject: "Registration Successful",
      text: `Hello ${name}, your ${role} account has been created successfully.`
    });  //Sends registration email.

    return res.status(201).json({
      message: `${role} registered successfully`,
      userId: result.insertId
    });   //Returns success response and inserted user id.
  } catch (error) {
    return res.status(500).json({
      message: "Registration failed",
      error: error.message
    }); //Returns error response
  }
};

const login = async (req, res) => {   //Creates login function.
  try {
    const { email, password, role } = req.body;   //Gets login values from request body.

    if (!email || !password || !role) {
      return res.status(400).json({ message: "Email, password and role are required" });
    } //Checks required fields.

    const table = getTableByRole(role);  //Gets correct table based on role.

    if (!table) {
      return res.status(400).json({ message: "Invalid role" });
    }  //Role validation.

    const [users] = await db.query(
      `SELECT * FROM ${table} WHERE email = ?`,
      [email]
    );  //Searches user by email in selected table.

    if (users.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }  //If no user found, return 404.

    const user = users[0];  //Gets first matching user.

    const isMatch = await bcrypt.compare(password, user.password);  //Compares entered password with hashed password in DB.

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password" });
    }  //If password does not match, return unauthorized.

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: role
      },  //Creates JWT payload.
      process.env.JWT_SECRET,  //Signs token using secret key.
      { expiresIn: "1h" }  //Token expires in 1 hour.
    );

    await transporter.sendMail({
      from: process.env.MAIL_USER,
      to: email,
      subject: "Login Alert",
      text: `Hello ${user.name}, you have logged in successfully as ${role}.`
    });  //Sends login email alert.

    return res.status(200).json({
      message: "Login successful",
      token
    });   //Returns success and JWT token.
  } catch (error) {
    return res.status(500).json({
      message: "Login failed",
      error: error.message
    });
  }
};

const profile = async (req, res) => {    //Creates protected route function.
  try {
    return res.status(200).json({
      message: "Protected profile accessed",
      user: req.user
    });   //Returns decoded JWT payload.This proves JWT middleware is working.
  } catch (error) {
    return res.status(500).json({
      message: "Profile fetch failed",
      error: error.message
    });
  }
};

module.exports = {
  register,
  login,
  profile
};