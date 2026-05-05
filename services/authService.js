const db = require("../config/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const transporter = require("../config/mailer");
const { getTableByRole, generateOTP } = require("../utils/helpers");
const { 
  AuthenticationError, 
  ForbiddenError, 
  NotFoundError, 
  RateLimitError, 
  ValidationError 
} = require("../utils/errors");
const {
  registrationTemplate,
  loginAlertTemplate,
  accountLockedTemplate,
  otpTemplate,
  accountUnlockedTemplate
} = require("../utils/emailTemplates");

/**
 * Internal helper to find a user across multiple role-based tables.
 * @param {string} email - The user's email address.
 * @returns {Object|null} - The user data and their role.
 */
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
      return { user: users[0], role: item.role };
    }
  }
  return null;
};

/**
 * Handles new user creation with role protection.
 * Only Admins can create other high-level accounts.
 */
const registerUser = async (name, email, password, role, requesterRole = null) => {
  // Enforce access control on role assignment
  if (role !== "public" && requesterRole !== "admin") {
    throw new ForbiddenError("Access Denied: High-level accounts must be created by an Admin.");
  }

  const table = getTableByRole(role);
  if (!table) throw new ValidationError("Invalid role provided");

  // Prevent duplicate registrations
  const [existingUsers] = await db.query(`SELECT * FROM ${table} WHERE email = ?`, [email]);
  if (existingUsers.length > 0) throw new ValidationError("Email already in use.");

  // Securely hash the password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Use a transaction to ensure database consistency
  const connection = await db.getConnection();
  await connection.beginTransaction();

  try {
    const [result] = await connection.query(
      `INSERT INTO ${table} (name, email, password) VALUES (?, ?, ?)`,
      [name, email, hashedPassword]
    );

    await connection.commit();

    // Notify user of successful registration via HTML email
    await transporter.sendMail({
      from: process.env.MAIL_USER,
      to: email,
      subject: "Welcome to our Platform",
      html: registrationTemplate(name, role)
    });

    return { message: "Account created successfully", userId: result.insertId };

  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
};

/**
 * Handles user authentication with advanced security throttling.
 * Implements exponential backoff and temporary lockouts for brute-force protection.
 */
const loginUser = async (email, password, ip, userAgent) => {
  const now = new Date();

  // Validate user existence
  const found = await findUserByEmail(email);
  if (!found) throw new NotFoundError("No account associated with this email.");

  const user = found.user;
  const role = found.role;

  // Retrieve security state for this user/IP combination
  const [statusRows] = await db.query(
    `SELECT * FROM login_security_status WHERE email = ? AND ip_address = ? AND role = ?`,
    [email, ip, role]
  );
  const status = statusRows[0];

  // Check for active blocks or throttles
  if (status?.is_support_locked) {
    throw new ForbiddenError("Account is permanently locked. Please contact our security team.");
  }

  if (status?.lock_until && now < new Date(status.lock_until)) {
    throw new ForbiddenError("Account temporarily blocked. Please wait 15 minutes.");
  }

  if (status?.throttle_until && now < new Date(status.throttle_until)) {
    const waitSeconds = Math.ceil((new Date(status.throttle_until) - now) / 1000);
    throw new RateLimitError(`Too many failed attempts. Wait ${waitSeconds} seconds.`, waitSeconds);
  }

  // Validate password
  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    // Record the failed attempt for security analysis
    const [existingTotalRows] = await db.query(
      `SELECT COUNT(*) AS count FROM login_failed_attempts WHERE email = ? AND ip_address = ? AND role = ?`,
      [email, ip, role]
    );
    const attemptCount = existingTotalRows[0].count + 1;

    const connection = await db.getConnection();
    await connection.beginTransaction();

    try {
      // Log the failure
      await connection.query(
        `INSERT INTO login_failed_attempts (email, ip_address, role, attempt_count, user_agent) VALUES (?, ?, ?, ?, ?)`,
        [email, ip, role, attemptCount, userAgent]
      );

      // Ensure a status record exists
      await connection.query(
        `INSERT IGNORE INTO login_security_status (email, ip_address, role) VALUES (?, ?, ?)`,
        [email, ip, role]
      );

      // Analyze failure patterns (15m and 5m windows)
      const [fifteenMinRows] = await connection.query(
        `SELECT COUNT(*) AS count FROM login_failed_attempts WHERE email = ? AND ip_address = ? AND role = ? AND attempted_at >= NOW() - INTERVAL 15 MINUTE`,
        [email, ip, role]
      );
      
      const [fiveMinRows] = await connection.query(
        `SELECT COUNT(*) AS count FROM login_failed_attempts WHERE email = ? AND ip_address = ? AND role = ? AND attempted_at >= NOW() - INTERVAL 5 MINUTE`,
        [email, ip, role]
      );

      const fifteenMinCount = fifteenMinRows[0].count;
      const fiveMinCount = fiveMinRows[0].count;

      // Handle severe brute force (10+ attempts) -> 15 min Block
      if (fifteenMinCount >= 10) {
        const [updatedRows] = await connection.query(`SELECT * FROM login_security_status WHERE email = ? AND ip_address = ? AND role = ?`, [email, ip, role]);
        const updated = updatedRows[0];
        let lockCount = (updated.lock_count || 0) + 1;
        
        // Permanent lock after 3 blocks
        const isSupportLocked = lockCount >= 3;
        const lockUntil = isSupportLocked ? null : new Date(Date.now() + 15 * 60 * 1000);

        await connection.query(
          `UPDATE login_security_status SET lock_until = ?, lock_count = ?, is_support_locked = ? WHERE email = ? AND ip_address = ? AND role = ?`,
          [lockUntil, lockCount, isSupportLocked, email, ip, role]
        );
        
        await connection.commit();

        // Send security alert email
        await transporter.sendMail({
          from: process.env.MAIL_USER,
          to: email,
          subject: "Security Alert: Account Restricted",
          html: accountLockedTemplate(isSupportLocked)
        });

        throw new ForbiddenError(isSupportLocked ? "Permanent security lock applied." : "Temporary 15-minute block applied.");
      }

      // Handle moderate brute force (5+ attempts) -> Throttling
      if (fiveMinCount >= 5) {
        const delayMs = 30 * 1000 * Math.pow(2, fiveMinCount - 5); // Exponential backoff
        const throttleUntil = new Date(Date.now() + delayMs);
        await connection.query(`UPDATE login_security_status SET throttle_until = ? WHERE email = ? AND ip_address = ? AND role = ?`, [throttleUntil, email, ip, role]);
        
        await connection.commit();

        await transporter.sendMail({
          from: process.env.MAIL_USER,
          to: email,
          subject: "Security Notification: Login Delay",
          html: otpTemplate("N/A") // Or a specific throttle alert template
        });

        throw new RateLimitError("Rate limit exceeded.", Math.ceil(delayMs / 1000));
      }

      await connection.commit();
      throw new AuthenticationError("Incorrect password.");

    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  // Clear security penalties on successful login
  await db.query(`DELETE FROM login_failed_attempts WHERE email = ? AND ip_address = ? AND role = ?`, [email, ip, role]);
  await db.query(`UPDATE login_security_status SET throttle_until = NULL, lock_until = NULL WHERE email = ? AND ip_address = ? AND role = ? AND is_support_locked = FALSE`, [email, ip, role]);

  // Generate session token
  const token = jwt.sign(
    { id: user.id, email: user.email, role, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  // Notify user of new login for security awareness
  await transporter.sendMail({
    from: process.env.MAIL_USER,
    to: email,
    subject: "Successful Login Alert",
    html: loginAlertTemplate(user.name, role)
  });

  return { message: "Welcome back!", token };
};

/**
 * Manually unlocks a user account.
 * Primarily used by Administrators to restore access.
 */
const unlockUser = async (targetEmail, targetRole) => {
  const found = await findUserByEmail(targetEmail);
  if (!found || found.role !== targetRole) throw new NotFoundError("User not found.");

  const connection = await db.getConnection();
  await connection.beginTransaction();

  try {
    // Reset all security counters
    await connection.query(
      `UPDATE login_security_status SET is_support_locked = FALSE, lock_count = 0, lock_until = NULL, throttle_until = NULL WHERE email = ? AND role = ?`,
      [targetEmail, targetRole]
    );

    await connection.query(`DELETE FROM login_failed_attempts WHERE email = ? AND role = ?`, [targetEmail, targetRole]);

    await connection.commit();

    // Notify user that their access is restored
    await transporter.sendMail({
      from: process.env.MAIL_USER,
      to: targetEmail,
      subject: "Account Access Restored",
      html: accountUnlockedTemplate()
    });

    return { message: "Account successfully unlocked." };

  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
};

/**
 * Generates and sends a hashed OTP for secure account recovery.
 */
const requestUnlockOtp = async (email) => {
  const found = await findUserByEmail(email);
  if (!found) throw new NotFoundError("Email not found.");

  const otp = generateOTP();
  const salt = await bcrypt.genSalt(10);
  const hashedOtp = await bcrypt.hash(otp, salt);
  
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  // Store hashed OTP for verification
  await db.query(
    `UPDATE login_security_status SET unlock_otp = ?, unlock_otp_expires_at = ? WHERE email = ? AND role = ?`,
    [hashedOtp, expiresAt, email, found.role]
  );

  // Send the plain code ONLY to the user's email
  await transporter.sendMail({
    from: process.env.MAIL_USER,
    to: email,
    subject: "Your Account Unlock Code",
    html: otpTemplate(otp)
  });

  return { message: "Security code sent to your email." };
};

/**
 * Verifies a hashed OTP to restore account access.
 */
const verifyUnlockOtp = async (email, otp) => {
  const found = await findUserByEmail(email);
  if (!found) throw new NotFoundError("User not found.");

  const [statusRows] = await db.query(`SELECT * FROM login_security_status WHERE email = ? AND role = ?`, [email, found.role]);
  const status = statusRows[0];

  if (!status || !status.unlock_otp) throw new ValidationError("No active recovery request found.");
  
  // Verify submitted code against stored hash
  const isMatch = await bcrypt.compare(otp, status.unlock_otp);
  if (!isMatch) throw new AuthenticationError("Invalid security code.");
  
  if (new Date() > new Date(status.unlock_otp_expires_at)) throw new AuthenticationError("Security code has expired.");

  const connection = await db.getConnection();
  await connection.beginTransaction();

  try {
    // Clear lock and sensitive data
    await connection.query(
      `UPDATE login_security_status SET is_support_locked = FALSE, lock_count = 0, lock_until = NULL, unlock_otp = NULL WHERE email = ? AND role = ?`,
      [email, found.role]
    );

    await connection.query(`DELETE FROM login_failed_attempts WHERE email = ? AND role = ?`, [email, found.role]);

    await connection.commit();
    return { message: "Identity verified. Account unlocked." };

  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
};

module.exports = {
  findUserByEmail,
  registerUser,
  loginUser,
  unlockUser,
  requestUnlockOtp,
  verifyUnlockOtp
};
