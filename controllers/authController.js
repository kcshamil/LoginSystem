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

const getClientIp = (req) => {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0] || // for proxy / real IP
    req.socket.remoteAddress ||                      // Node default
    req.ip                                           // fallback
  );
};


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

const login = async (req, res) => {
  try {
    const { email, password, role } = req.body;
    const ip = getClientIp(req);
    const now = new Date();

    if (!email || !password || !role) {
      return res.status(400).json({
        message: "Email, password and role are required"
      });
    }

    const table = getTableByRole(role);

    if (!table) {
      return res.status(400).json({ message: "Invalid role" });
    }

    const [users] = await db.query(
      `SELECT * FROM ${table} WHERE email = ?`,
      [email]
    );

    if (users.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = users[0];

    const [attemptRows] = await db.query(
      "SELECT * FROM login_attempts WHERE email = ? AND ip_address = ?",
      [email, ip]
    );

    const attempt = attemptRows[0];

    if (attempt && attempt.is_support_locked) {
      await transporter.sendMail({
        from: process.env.MAIL_USER,
        to: email,
        subject: "Account Locked - Support Required",
        text: "Your account has been locked due to repeated failed login attempts. Please contact support to regain access."
      });

      return res.status(403).json({
        message: "Your account has been locked, please contact support",
        contactSupport: "/contact-us"
      });
    }

    if (attempt && attempt.lock_until && now < new Date(attempt.lock_until)) {
      await transporter.sendMail({
        from: process.env.MAIL_USER,
        to: email,
        subject: "Account Temporarily Blocked",
        text: "Your account has been temporarily blocked due to multiple failed login attempts. Please try again later."
      });

      return res.status(403).json({
        message: "Your account has been blocked, try again later"
      });
    }

    if (
      attempt &&
      attempt.throttle_until &&
      now < new Date(attempt.throttle_until)
    ) {
      const waitSeconds = Math.ceil(
        (new Date(attempt.throttle_until) - now) / 1000
      );

      return res.status(429).json({
        message: `Too many failed attempts. Try again after ${waitSeconds} seconds.`,
        retryAfterSeconds: waitSeconds
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      let failedAttempts = 1;
      let firstFailedAt = now;
      let lockCount = 0;
      let firstLockAt = null;
      let throttleUntil = null;
      let lockUntil = null;
      let isSupportLocked = false;

      if (attempt) {
        const firstFailedTime = attempt.first_failed_at
          ? new Date(attempt.first_failed_at)
          : now;

        const diffFromFirstFailed = now - firstFailedTime;

        if (diffFromFirstFailed <= 5 * 60 * 1000) {
          failedAttempts = attempt.failed_attempts + 1;
          firstFailedAt = firstFailedTime;
        } else {
          failedAttempts = 1;
          firstFailedAt = now;
        }

        lockCount = attempt.lock_count || 0;
        firstLockAt = attempt.first_lock_at;
      }

      if (failedAttempts >= 5) {
        const breachCount = failedAttempts - 4;
        const delayMs = 30 * 1000 * Math.pow(2, breachCount - 1);
        throttleUntil = new Date(Date.now() + delayMs);
      }

      if (failedAttempts >= 10) {
        lockUntil = new Date(Date.now() + 15 * 60 * 1000);

        if (firstLockAt) {
          const diffFromFirstLock = now - new Date(firstLockAt);

          if (diffFromFirstLock <= 24 * 60 * 60 * 1000) {
            lockCount += 1;
          } else {
            lockCount = 1;
            firstLockAt = now;
          }
        } else {
          lockCount = 1;
          firstLockAt = now;
        }

        failedAttempts = 0;
        firstFailedAt = null;
        throttleUntil = null;

        if (lockCount >= 3) {
          isSupportLocked = true;
        }
      }

      if (attempt) {
        await db.query(
          `UPDATE login_attempts 
           SET failed_attempts = ?, 
               first_failed_at = ?, 
               last_attempt = NOW(), 
               throttle_until = ?, 
               lock_until = ?, 
               lock_count = ?, 
               first_lock_at = ?, 
               is_support_locked = ?
           WHERE email = ? AND ip_address = ?`,
          [
            failedAttempts,
            firstFailedAt,
            throttleUntil,
            lockUntil,
            lockCount,
            firstLockAt,
            isSupportLocked,
            email,
            ip
          ]
        );
      } else {
        await db.query(
          `INSERT INTO login_attempts 
           (email, ip_address, failed_attempts, first_failed_at, last_attempt, throttle_until, lock_until, lock_count, first_lock_at, is_support_locked)
           VALUES (?, ?, ?, ?, NOW(), ?, ?, ?, ?, ?)`,
          [
            email,
            ip,
            failedAttempts,
            firstFailedAt,
            throttleUntil,
            lockUntil,
            lockCount,
            firstLockAt,
            isSupportLocked
          ]
        );
      }

      if (isSupportLocked) {
        await transporter.sendMail({
          from: process.env.MAIL_USER,
          to: email,
          subject: "Account Locked - Support Required",
          text: "Your account has been locked due to repeated temporary lockouts. Please contact support to regain access."
        });

        return res.status(403).json({
          message: "Your account has been locked, please contact support",
          contactSupport: "/contact-us"
        });
      }

      if (lockUntil) {
        await transporter.sendMail({
          from: process.env.MAIL_USER,
          to: email,
          subject: "Account Temporarily Blocked",
          text: "Your account has been blocked for 15 minutes due to multiple failed login attempts."
        });

        return res.status(403).json({
          message: "Your account has been blocked, try again later"
        });
      }

      if (throttleUntil) {
        const waitSeconds = Math.ceil((throttleUntil - now) / 1000);

        await transporter.sendMail({
          from: process.env.MAIL_USER,
          to: email,
          subject: "Security Alert",
          text: `Multiple failed login attempts detected. Please try again after ${waitSeconds} seconds.`
        });

        return res.status(429).json({
          message: `Too many failed attempts. Try again after ${waitSeconds} seconds.`,
          retryAfterSeconds: waitSeconds
        });
      }

      await transporter.sendMail({
        from: process.env.MAIL_USER,
        to: email,
        subject: "Security Alert",
        text: "A failed login attempt was detected on your account."
      });

      return res.status(401).json({
        message: "Invalid password"
      });
    }

    await db.query(
      "DELETE FROM login_attempts WHERE email = ? AND ip_address = ?",
      [email, ip]
    );

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: role
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    await transporter.sendMail({
      from: process.env.MAIL_USER,
      to: email,
      subject: "Login Alert",
      text: `Hello ${user.name}, you have logged in successfully as ${role}.`
    });

    return res.status(200).json({
      message: "Login successful",
      token
    });
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

const subadminOnly = (req, res) => {   //Creates a controller function named subAdminOnly.
  if (req.user.role !== "subadmin" && req.user.role !== "admin") {    //If user is NOT subadmin AND NOT admin → block access
    return res.status(403).json({
      message: "Access denied! Subadmin or Admin only "
    })
  }   //If role is not allowed, send 403 Forbidden.(User is logged in, but does not have permission.)

  res.status(200).json({
    message: "Welcome Subadmin/Admin",
    user: req.user
  })
}

const adminOnly = (req, res) => {
  // check role
  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Access denied! Admin only"
    })
  }

  res.status(200).json({
    message: "Welcome Admin",
    user: req.user
  })
}

module.exports = {
  register,
  login,
  profile,
  adminOnly,
  subadminOnly
};