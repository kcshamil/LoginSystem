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

const findUserByEmail = async (email) => {
  const tables = [
    { table: "public_users", role: "public" },
    { table: "sub_admins", role: "subadmin" },
    { table: "admins", role: "admin" }
  ];

  for (const item of tables) {
    const [users] = await db.query(
      `SELECT * FROM ${item.table} WHERE email = ?`,
      [email]
    );

    if (users.length > 0) {
      return {
        user: users[0],
        role: item.role
      };
    }
  }

  return null;
};

const getClientIp = (req) => {

  let ip =
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket.remoteAddress ||
    req.ip;

  if (ip === "::1") ip = "127.0.0.1";
  if (ip.startsWith("::ffff:")) ip = ip.replace("::ffff:", "");

  return ip;
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

// Login controller function
const login = async (req, res) => {
  try {
    // Get email, password, and role from frontend request body
    const { email, password } = req.body;

    // Get user's IP address
    const ip = getClientIp(req);

    // Store current date and time
    const now = new Date();

    // Check if email, password is missing
    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required"
      });
    }

    const found = await findUserByEmail(email);

    if (!found) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = found.user;
    const role = found.role;
    // Get login security status for this email + IP + role
    const [statusRows] = await db.query(
      `SELECT * FROM login_security_status
       WHERE email = ? AND ip_address = ? AND role = ?`,
      [email, ip, role]
    );

    // Store security status
    const status = statusRows[0];

    // Check if account is permanently locked by support condition
    if (status?.is_support_locked) {
      // Send account locked email
      await transporter.sendMail({
        from: process.env.MAIL_USER,
        to: email,
        subject: "Account Locked - Support Required",
        text: "Your account has been locked due to repeated failed login attempts. Please contact support."
      });

      // Stop login and ask user to contact support
      return res.status(403).json({
        message: "Your account has been locked, please contact support",
        contactSupport: "/contact-us"
      });
    }

    // Check temporary lock
    // If lock_until time exists and current time is less than lock_until
    if (status?.lock_until && now < new Date(status.lock_until)) {
      return res.status(403).json({
        message: "Your account has been blocked, try again later"
      });
    }

    // Check throttling delay
    // If throttle_until exists and current time is less than throttle_until
    if (status?.throttle_until && now < new Date(status.throttle_until)) {
      // Calculate remaining waiting time in seconds
      const waitSeconds = Math.ceil(
        (new Date(status.throttle_until) - now) / 1000
      );

      // Send too many attempts response
      return res.status(429).json({
        message: `Too many failed attempts. Try again after ${waitSeconds} seconds.`,
        retryAfterSeconds: waitSeconds
      });
    }

    // Compare entered password with hashed password in database
    const isMatch = await bcrypt.compare(password, user.password);

    // If password is wrong
    if (!isMatch) {
      // Save failed login attempt in database
      await db.query(
        `INSERT INTO login_failed_attempts
         (email, ip_address, role)
         VALUES (?, ?, ?)`,
        [email, ip, role]
      );

      // Create security status row if it does not already exist
      await db.query(
        `INSERT IGNORE INTO login_security_status
         (email, ip_address, role)
         VALUES (?, ?, ?)`,
        [email, ip, role]
      );

      // Count failed attempts in last 5 minutes
      const [fiveMinRows] = await db.query(
        `SELECT COUNT(*) AS count
         FROM login_failed_attempts
         WHERE email = ?
         AND ip_address = ?
         AND role = ?
         AND attempted_at >= NOW() - INTERVAL 5 MINUTE`,
        [email, ip, role]
      );

      // Count failed attempts in last 15 minutes
      const [fifteenMinRows] = await db.query(
        `SELECT COUNT(*) AS count
         FROM login_failed_attempts
         WHERE email = ?
         AND ip_address = ?
         AND role = ?
         AND attempted_at >= NOW() - INTERVAL 15 MINUTE`,
        [email, ip, role]
      );

      // Store counts
      const fiveMinCount = fiveMinRows[0].count;
      const fifteenMinCount = fifteenMinRows[0].count;

      // Temporary lockout condition
      // If user has 10 failed attempts within 15 minutes
      if (fifteenMinCount >= 10) {
        // Get updated security status
        const [updatedStatusRows] = await db.query(
          `SELECT * FROM login_security_status
           WHERE email = ? AND ip_address = ? AND role = ?`,
          [email, ip, role]
        );

        const updatedStatus = updatedStatusRows[0];

        // Get current lock count, default is 0
        let lockCount = updatedStatus.lock_count || 0;

        // Get first lock time
        let firstLockAt = updatedStatus.first_lock_at;

        // If first lock time already exists
        if (firstLockAt) {
          // Find difference between now and first lock time
          const diff = now - new Date(firstLockAt);

          // If within 24 hours, increase lock count
          if (diff <= 24 * 60 * 60 * 1000) {
            lockCount += 1;
          } else {
            // If more than 24 hours, reset lock count
            lockCount = 1;
            firstLockAt = now;
          }
        } else {
          // First temporary lock
          lockCount = 1;
          firstLockAt = now;
        }

        // If 3 temporary locks happen within 24 hours, support lock account
        const isSupportLocked = lockCount >= 3;

        // If support locked, no lock_until needed
        // Otherwise block account for 15 minutes
        const lockUntil = isSupportLocked
          ? null
          : new Date(Date.now() + 15 * 60 * 1000);

        // Update security status table
        await db.query(
          `UPDATE login_security_status
           SET lock_until = ?,
               throttle_until = NULL,
               lock_count = ?,
               first_lock_at = ?,
               is_support_locked = ?
           WHERE email = ? AND ip_address = ? AND role = ?`,
          [
            lockUntil,
            lockCount,
            firstLockAt,
            isSupportLocked,
            email,
            ip,
            role
          ]
        );

        // Send email for temporary block or support lock
        await transporter.sendMail({
          from: process.env.MAIL_USER,
          to: email,
          subject: isSupportLocked
            ? "Account Locked - Support Required"
            : "Account Temporarily Blocked",
          text: isSupportLocked
            ? "Your account has been locked due to repeated temporary lockouts. Please contact support."
            : "Your account has been blocked for 15 minutes due to multiple failed login attempts."
        });

        // If support locked, stop login
        if (isSupportLocked) {
          return res.status(403).json({
            message: "Your account has been locked, please contact support",
            contactSupport: "/contact-us"
          });
        }

        // Temporary block response
        return res.status(403).json({
          message: "Your account has been blocked, try again later"
        });
      }

      // Throttling condition
      // If user has 5 failed attempts within 5 minutes
      if (fiveMinCount >= 5) {
        // Calculate breach count
        // 5th fail = 1, 6th fail = 2, 7th fail = 3
        const breachCount = fiveMinCount - 4;

        // Progressive delay:
        // 5th fail = 30 seconds
        // 6th fail = 60 seconds
        // 7th fail = 120 seconds
        const delayMs = 30 * 1000 * Math.pow(2, breachCount - 1);

        // Create throttle end time
        const throttleUntil = new Date(Date.now() + delayMs);

        // Convert delay to seconds
        const waitSeconds = Math.ceil(delayMs / 1000);

        // Save throttle time in database
        await db.query(
          `UPDATE login_security_status
           SET throttle_until = ?
           WHERE email = ? AND ip_address = ? AND role = ?`,
          [throttleUntil, email, ip, role]
        );

        // Send security alert email
        await transporter.sendMail({
          from: process.env.MAIL_USER,
          to: email,
          subject: "Security Alert",
          text: `Multiple failed login attempts detected. Please try again after ${waitSeconds} seconds.`
        });

        // Send throttling response
        return res.status(429).json({
          message: `Too many failed attempts. Try again after ${waitSeconds} seconds.`,
          retryAfterSeconds: waitSeconds
        });
      }

      // Send normal failed login email
      transporter.sendMail({
        from: process.env.MAIL_USER,
        to: email,
        subject: "Security Alert",
        text: "A failed login attempt was detected on your account."
      }).catch(err => console.log(err));

      // Wrong password response
      return res.status(401).json({
        message: "Invalid password"
      });
    }

    // If login success, delete failed attempts for this email + IP + role
    await db.query(
      `DELETE FROM login_failed_attempts
       WHERE email = ? AND ip_address = ? AND role = ?`,
      [email, ip, role]
    );

    // Clear throttle and temporary lock after successful login
    // But do not clear support lock
    await db.query(
      `UPDATE login_security_status
       SET throttle_until = NULL,
           lock_until = NULL
       WHERE email = ? AND ip_address = ? AND role = ?
       AND is_support_locked = FALSE`,
      [email, ip, role]
    );

    // Create JWT token
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Send successful login email
    await transporter.sendMail({
      from: process.env.MAIL_USER,
      to: email,
      subject: "Login Alert",
      text: `Hello ${user.name}, you have logged in successfully as ${role}.`
    });

    // Send success response with token
    return res.status(200).json({
      message: "Login successful",
      token
    });

  } catch (error) {
    // If any server error happens, send 500 response
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