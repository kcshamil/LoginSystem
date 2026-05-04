const db = require("../config/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const transporter = require("../config/mailer");
const { getTableByRole, generateOTP } = require("../utils/helpers");

/**
 * Helper to search across all role tables for an email address.
 * Identifies whether a user is public, subadmin, or admin.
 */
const findUserByEmail = async (email) => {
  const tables = [
    { table: "public_users", role: "public" },
    { table: "sub_admins", role: "subadmin" },
    { table: "admins", role: "admin" }
  ];

  // Iterate through all user tables to find the matching email
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

  return null; // User does not exist
};

/**
 * Service to register a new user.
 * Hashes passwords and creates necessary database records.
 */
const registerUser = async (name, email, password, role) => {
  const table = getTableByRole(role);

  if (!table) {
    return { statusCode: 400, json: { message: "Invalid role" } };
  }

  // Check if email is already in use
  const [existingUsers] = await db.query(
    `SELECT * FROM ${table} WHERE email = ?`,
    [email]
  );

  if (existingUsers.length > 0) {
    return { statusCode: 409, json: { message: "User already exists" } };
  }

  // Cryptographically hash the password (Industry Standard: bcrypt 10 rounds)
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Insert user into the corresponding role table
  const [result] = await db.query(
    `INSERT INTO ${table} (name, email, password) VALUES (?, ?, ?)`,
    [name, email, hashedPassword]
  );

  // Send welcome email
  await transporter.sendMail({
    from: process.env.MAIL_USER,
    to: email,
    subject: "Registration Successful",
    text: `Hello ${name}, your ${role} account has been created successfully.`
  });

  return {
    statusCode: 201,
    json: { message: `${role} registered successfully`, userId: result.insertId }
  };
};

/**
 * Service for highly secure, multi-tiered Login logic.
 * Enforces exponential throttling, 15-minute temporary blocks, and 24-hour support locks.
 */
const loginUser = async (email, password, ip, userAgent) => {
  const now = new Date();

  // 1. Verify user existence
  const found = await findUserByEmail(email);
  if (!found) {
    return { statusCode: 404, json: { message: "User not found" } };
  }

  const user = found.user;
  const role = found.role;

  // 2. Fetch the current security state for this User + IP combination
  const [statusRows] = await db.query(
    `SELECT * FROM login_security_status
     WHERE email = ? AND ip_address = ? AND role = ?`,
    [email, ip, role]
  );

  const status = statusRows[0];

  // 3. ENFORCEMENT STAGE: Check if user is currently locked/throttled before checking password

  // Check if account is permanently locked by Support (3 lockouts in 24 hours)
  if (status?.is_support_locked) {
    await transporter.sendMail({
      from: process.env.MAIL_USER,
      to: email,
      subject: "Account Locked - Action Required",
      html: `<p>Your account has been locked for your security due to repeated failed login attempts.</p>
             <p>To regain access to your account securely, please click the button below to verify your identity and receive an unlock code:</p>
             <div style="margin: 25px 0;">
               <a href="https://loginsystem.com/unlock-account" style="background-color: #0066ff; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block; font-family: sans-serif;">Unlock My Account</a>
             </div>
             <p style="color: #666; font-size: 14px;">If you need further assistance, please <a href="https://loginsystem.com/contact-us">Contact Support</a>.</p>`
    });

    return {
      statusCode: 403,
      json: {
        message: "Your account has been locked, please contact support",
        contactSupport: "/contact-us"
      }
    };
  }

  // Check if account is serving a 15-minute temporary lockout
  if (status?.lock_until && now < new Date(status.lock_until)) {
    return { statusCode: 403, json: { message: "Your account has been blocked, try again later" } };
  }

  // Check if account is serving an exponential throttle delay (e.g., 30s, 60s)
  if (status?.throttle_until && now < new Date(status.throttle_until)) {
    const waitSeconds = Math.ceil((new Date(status.throttle_until) - now) / 1000);
    return {
      statusCode: 429,
      json: { message: `Too many failed attempts. Try again after ${waitSeconds} seconds.`, retryAfterSeconds: waitSeconds }
    };
  }

  // 4. AUTHENTICATION STAGE: Validate password
  const isMatch = await bcrypt.compare(password, user.password);

  // 5. FAILURE HANDLING: If the password was wrong, process strikes and lockouts
  if (!isMatch) {

    // Audit Logging: Record the failed attempt with User-Agent and absolute total count
    const [existingTotalRows] = await db.query(
      `SELECT COUNT(*) AS count
       FROM login_failed_attempts
       WHERE email = ? AND ip_address = ? AND role = ?`,
      [email, ip, role]
    );

    const attemptCount = existingTotalRows[0].count + 1;

    await db.query(
      `INSERT INTO login_failed_attempts
       (email, ip_address, role, attempt_count, user_agent)
       VALUES (?, ?, ?, ?, ?)`,
      [email, ip, role, attemptCount, userAgent]
    );

    // Ensure a security status record exists for tracking penalties
    await db.query(
      `INSERT IGNORE INTO login_security_status
       (email, ip_address, role)
       VALUES (?, ?, ?)`,
      [email, ip, role]
    );

    // Calculate rolling windows for security triggers
    const [fiveMinRows] = await db.query(
      `SELECT COUNT(*) AS count FROM login_failed_attempts
       WHERE email = ? AND ip_address = ? AND role = ?
       AND attempted_at >= NOW() - INTERVAL 5 MINUTE`,
      [email, ip, role]
    );

    const [fifteenMinRows] = await db.query(
      `SELECT COUNT(*) AS count FROM login_failed_attempts
       WHERE email = ? AND ip_address = ? AND role = ?
       AND attempted_at >= NOW() - INTERVAL 15 MINUTE`,
      [email, ip, role]
    );

    const fiveMinCount = fiveMinRows[0].count;
    const fifteenMinCount = fifteenMinRows[0].count;

    // SCENARIO A: 15-Minute Temporary Lockout (10 failures within 15 minutes)
    if (fifteenMinCount >= 10) {
      const [updatedStatusRows] = await db.query(
        `SELECT * FROM login_security_status WHERE email = ? AND ip_address = ? AND role = ?`,
        [email, ip, role]
      );

      const updatedStatus = updatedStatusRows[0];
      let lockCount = updatedStatus.lock_count || 0;
      let firstLockAt = updatedStatus.first_lock_at;

      // 24-Hour Escalation Logic
      if (firstLockAt) {
        const diff = now - new Date(firstLockAt);
        if (diff <= 24 * 60 * 60 * 1000) {
          lockCount += 1; // Increase strikes within the 24-hour window
        } else {
          lockCount = 1;  // Reset if more than 24 hours have passed
          firstLockAt = now;
        }
      } else {
        lockCount = 1;
        firstLockAt = now;
      }

      // If they hit 3 lockouts in 24 hours, apply permanent Support Lock
      const isSupportLocked = lockCount >= 3;
      const lockUntil = isSupportLocked ? null : new Date(Date.now() + 15 * 60 * 1000);

      await db.query(
        `UPDATE login_security_status
         SET lock_until = ?, throttle_until = NULL, lock_count = ?, first_lock_at = ?, is_support_locked = ?
         WHERE email = ? AND ip_address = ? AND role = ?`,
        [lockUntil, lockCount, firstLockAt, isSupportLocked, email, ip, role]
      );

      await transporter.sendMail({
        from: process.env.MAIL_USER,
        to: email,
        subject: isSupportLocked ? "Account Locked - Action Required" : "Account Temporarily Blocked",
        html: isSupportLocked
          ? `<p>Your account has been locked for your security due to repeated temporary lockouts.</p>
             <p>To regain access to your account securely, please click the button below to verify your identity and receive an unlock code:</p>
             <div style="margin: 25px 0;">
               <a href="https://loginsystem.com/unlock-account" style="background-color: #0066ff; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block; font-family: sans-serif;">Unlock My Account</a>
             </div>
             <p style="color: #666; font-size: 14px;">If you need further assistance, please <a href="https://loginsystem.com/contact-us">Contact Support</a>.</p>`
          : `<p>Your account has been blocked for 15 minutes due to multiple failed login attempts.</p>`
      });

      if (isSupportLocked) {
        return {
          statusCode: 403,
          json: {
            message: "Your account has been locked, please contact support",
            contactSupport: "/contact-us"
          }
        };
      }

      return { statusCode: 403, json: { message: "Your account has been blocked, try again later" } };
    }

    // SCENARIO B: Progressive Throttling (5 failures within 5 minutes)
    if (fiveMinCount >= 5) {
      const breachCount = fiveMinCount - 4; // 1st breach at 5, 2nd at 6, etc.
      const delayMs = 30 * 1000 * Math.pow(2, breachCount - 1); // Exponential: 30s, 60s, 120s...
      const throttleUntil = new Date(Date.now() + delayMs);
      const waitSeconds = Math.ceil(delayMs / 1000);

      await db.query(
        `UPDATE login_security_status SET throttle_until = ? WHERE email = ? AND ip_address = ? AND role = ?`,
        [throttleUntil, email, ip, role]
      );

      await transporter.sendMail({
        from: process.env.MAIL_USER,
        to: email,
        subject: "Security Alert",
        text: `Multiple failed login attempts detected. Please try again after ${waitSeconds} seconds.`
      });

      return { statusCode: 429, json: { message: `Too many failed attempts. Try again after ${waitSeconds} seconds.`, retryAfterSeconds: waitSeconds } };
    }

    // SCENARIO C: Standard failure (Below thresholds)
    return { statusCode: 401, json: { message: "Invalid password" } };
  }

  // 6. SUCCESS HANDLING: Clear audit history, reset temporary timers (keep 24-hour escalation history)
  await db.query(
    `DELETE FROM login_failed_attempts
     WHERE email = ? AND ip_address = ? AND role = ?`,
    [email, ip, role]
  );

  await db.query(
    `UPDATE login_security_status
     SET throttle_until = NULL, lock_until = NULL
     WHERE email = ? AND ip_address = ? AND role = ? AND is_support_locked = FALSE`,
    [email, ip, role]
  );

  // Issue JSON Web Token for authentication
  const token = jwt.sign(
    { id: user.id, email: user.email, role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  await transporter.sendMail({
    from: process.env.MAIL_USER,
    to: email,
    subject: "Login Alert",
    text: `Hello ${user.name}, you have logged in successfully as ${role}.`
  });

  return { statusCode: 200, json: { message: "Login successful", token } };
};

/**
 * Service to unlock a user account by an administrator.
 * Clears all security penalties and audit logs for the targeted user, then sends a confirmation email.
 */
const unlockUser = async (targetEmail, targetRole) => {
  // 1. Verify user exists first to prevent unlocking non-existent accounts
  const found = await findUserByEmail(targetEmail);
  if (!found || found.role !== targetRole) {
    return { statusCode: 404, json: { message: "User not found or role mismatch" } };
  }

  // 2. Clear all penalties in the security status table
  await db.query(
    `UPDATE login_security_status
     SET is_support_locked = FALSE, 
         lock_count = 0, 
         first_lock_at = NULL, 
         lock_until = NULL, 
         throttle_until = NULL
     WHERE email = ? AND role = ?`,
    [targetEmail, targetRole]
  );

  // 3. Clear their failed attempt history so they start with a clean slate
  await db.query(
    `DELETE FROM login_failed_attempts
     WHERE email = ? AND role = ?`,
    [targetEmail, targetRole]
  );

  // 4. Send the confirmation email
  await transporter.sendMail({
    from: process.env.MAIL_USER,
    to: targetEmail,
    subject: "Account Unlocked",
    html: `<p>Good news! Your account has been successfully unlocked by our support team.</p>
           <p>You may now return to the login screen and access your account.</p>`
  });

  return { statusCode: 200, json: { message: "User account successfully unlocked" } };
};

/**
 * Service to request an OTP for self-service account unlock.
 * Generates an OTP, saves it with an expiration time, and emails it.
 */
const requestUnlockOtp = async (email) => {
  // 1. Verify user exists and determine their true role securely
  const found = await findUserByEmail(email);
  if (!found) {
    return { statusCode: 404, json: { message: "User not found" } };
  }
  const role = found.role;

  // 2. Check if the user is actually locked. If not, no need for OTP.
  const [statusRows] = await db.query(
    `SELECT * FROM login_security_status WHERE email = ? AND role = ?`,
    [email, role]
  );

  const status = statusRows[0];
  if (!status || (!status.is_support_locked && !status.lock_until)) {
    return { statusCode: 400, json: { message: "Account is not currently locked" } };
  }

  // 3. Generate OTP and calculate expiration (10 minutes)
  const otp = generateOTP();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  // 4. Save OTP to database
  await db.query(
    `UPDATE login_security_status
     SET unlock_otp = ?, unlock_otp_expires_at = ?
     WHERE email = ? AND role = ?`,
    [otp, expiresAt, email, role]
  );

  // 5. Email the OTP to the user
  await transporter.sendMail({
    from: process.env.MAIL_USER,
    to: email,
    subject: "Account Unlock OTP Code",
    html: `<p>You have requested to unlock your account.</p>
           <p>Your One-Time Password (OTP) is: <strong>${otp}</strong></p>
           <p>This code will expire in 10 minutes. If you did not request this, please ignore this email.</p>`
  });

  return { statusCode: 200, json: { message: "OTP sent successfully to your email" } };
};

/**
 * Service to verify an OTP and unlock the account.
 */
const verifyUnlockOtp = async (email, otp) => {
  const now = new Date();

  // 1. Verify user exists and securely determine their role
  const found = await findUserByEmail(email);
  if (!found) {
    return { statusCode: 404, json: { message: "User not found" } };
  }
  const role = found.role;

  // 2. Check the OTP in the database
  const [statusRows] = await db.query(
    `SELECT * FROM login_security_status WHERE email = ? AND role = ?`,
    [email, role]
  );

  const status = statusRows[0];

  if (!status || !status.unlock_otp) {
    return { statusCode: 400, json: { message: "No OTP request found for this account" } };
  }

  // 3. Validate the OTP and Expiration
  if (status.unlock_otp !== otp) {
    return { statusCode: 401, json: { message: "Invalid OTP code" } };
  }

  if (now > new Date(status.unlock_otp_expires_at)) {
    return { statusCode: 401, json: { message: "OTP code has expired. Please request a new one." } };
  }

  // 4. OTP is valid! Unlock the account by clearing all penalties
  await db.query(
    `UPDATE login_security_status
     SET is_support_locked = FALSE, 
         lock_count = 0, 
         first_lock_at = NULL, 
         lock_until = NULL, 
         throttle_until = NULL,
         unlock_otp = NULL,
         unlock_otp_expires_at = NULL
     WHERE email = ? AND role = ?`,
    [email, role]
  );

  // 5. Clear failed attempts history
  await db.query(
    `DELETE FROM login_failed_attempts
     WHERE email = ? AND role = ?`,
    [email, role]
  );

  // 6. Send confirmation email
  await transporter.sendMail({
    from: process.env.MAIL_USER,
    to: email,
    subject: "Account Successfully Unlocked",
    html: `<p>Your account has been successfully unlocked using OTP verification.</p>
           <p>You may now return to the login screen and securely access your account.</p>`
  });

  return { statusCode: 200, json: { message: "Account unlocked successfully. You may now log in." } };
};

module.exports = {
  findUserByEmail,
  registerUser,
  loginUser,
  unlockUser,
  requestUnlockOtp,
  verifyUnlockOtp
};
