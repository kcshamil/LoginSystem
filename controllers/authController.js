const { getClientIp } = require("../utils/helpers");
const authService = require("../services/authService");

/**
 * Handles User Registration
 * Receives incoming user data, validates it, and delegates to authService to create the user.
 */
const register = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Validate that all required fields are provided
    if (!name || !email || !password || !role) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Call the Service Layer to handle database insertion and email sending
    const result = await authService.registerUser(name, email, password, role);
    
    // Return the specific status code and JSON object provided by the service
    return res.status(result.statusCode).json(result.json);

  } catch (error) {
    // Catch any unexpected server errors
    return res.status(500).json({
      message: "Registration failed",
      error: error.message
    });
  }
};

/**
 * Handles User Login & Security Checks
 * Extracts credentials and network info (IP, User-Agent), then delegates to authService.
 */
const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Extract IP and User-Agent for security auditing
    const ip = getClientIp(req);
    const userAgent = req.headers['user-agent'] || 'Unknown Device';

    // Validate request body
    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required"
      });
    }

    // Call the Service Layer to perform highly secure, multi-tiered login checks
    const result = await authService.loginUser(email, password, ip, userAgent);
    
    return res.status(result.statusCode).json(result.json);

  } catch (error) {
    // Catch any unexpected server errors
    return res.status(500).json({
      message: "Login failed",
      error: error.message
    });
  }
};

/**
 * Protected Profile Route
 * Returns the decoded JWT payload to prove authentication works.
 */
const profile = async (req, res) => {
  try {
    return res.status(200).json({
      message: "Protected profile accessed",
      user: req.user
    });
  } catch (error) {
    return res.status(500).json({
      message: "Profile fetch failed",
      error: error.message
    });
  }
};

/**
 * Subadmin and Admin Only Route
 * Role-Based Access Control (RBAC) middleware check.
 */
const subadminOnly = (req, res) => {
  // Block access if the user is a public user
  if (req.user.role !== "subadmin" && req.user.role !== "admin") {
    return res.status(403).json({
      message: "Access denied! Subadmin or Admin only "
    })
  }

  res.status(200).json({
    message: "Welcome Subadmin/Admin",
    user: req.user
  })
}

/**
 * Admin Only Route
 * Strict Role-Based Access Control (RBAC) for top-level administrators.
 */
const adminOnly = (req, res) => {
  // Block access for anyone except standard admins
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

/**
 * Admin Route to manually unlock a user account.
 * Requires the user making the request to have an 'admin' role.
 */
const unlockAccount = async (req, res) => {
  try {
    // 1. Strict RBAC: Only Admins can unlock accounts
    if (req.user.role !== "admin") {
      return res.status(403).json({
        message: "Access denied! Only administrators can unlock accounts."
      });
    }

    const { targetEmail, targetRole } = req.body;

    if (!targetEmail || !targetRole) {
      return res.status(400).json({
        message: "targetEmail and targetRole are required"
      });
    }

    // 2. Delegate to Service Layer
    const result = await authService.unlockUser(targetEmail, targetRole);
    return res.status(result.statusCode).json(result.json);

  } catch (error) {
    return res.status(500).json({
      message: "Unlock failed",
      error: error.message
    });
  }
};

/**
 * Public Route to request an OTP for unlocking an account.
 * Endpoint used by the frontend when a user clicks 'Unlock Account'.
 */
const requestUnlockOtp = async (req, res) => {
  try {
    const { email } = req.body;
    
    // Validate that required fields are provided
    if (!email) {
      return res.status(400).json({ message: "email is required" });
    }
    
    // Delegate OTP generation, storage, and email delivery to the Service Layer
    const result = await authService.requestUnlockOtp(email);
    return res.status(result.statusCode).json(result.json);
    
  } catch (error) {
    return res.status(500).json({ message: "Failed to request OTP", error: error.message });
  }
};

/**
 * Public Route to verify the OTP and unlock the account.
 * Endpoint used when the user submits the 6-digit code sent to their email.
 */
const verifyUnlockOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    // Validate request body
    if (!email || !otp) {
      return res.status(400).json({ message: "email and otp are required" });
    }
    
    // Delegate OTP validation and security clearance to the Service Layer
    const result = await authService.verifyUnlockOtp(email, otp);
    return res.status(result.statusCode).json(result.json);
    
  } catch (error) {
    return res.status(500).json({ message: "Failed to verify OTP", error: error.message });
  }
};

module.exports = {
  register,
  login,
  profile,
  adminOnly,
  subadminOnly,
  unlockAccount,
  requestUnlockOtp,
  verifyUnlockOtp
};