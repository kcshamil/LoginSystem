/**
 * Professional HTML Email Templates
 * Responsive designs used for all automated system notifications.
 */

/**
 * Wraps dynamic content in a professional email frame.
 * @param {string} content - The main body HTML.
 * @returns {string} - Complete HTML document.
 */
const getBaseTemplate = (content) => `
<!DOCTYPE html>
<html>
<head>
    <style>
        .body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px; }
        .header { text-align: center; padding-bottom: 20px; border-bottom: 2px solid #f4f4f4; }
        .content { padding: 20px 0; }
        .footer { text-align: center; font-size: 12px; color: #888; border-top: 2px solid #f4f4f4; padding-top: 20px; }
        .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: #ffffff !important; text-decoration: none; border-radius: 5px; font-weight: bold; margin-top: 20px; }
        .warning-box { background-color: #fff3cd; border-left: 5px solid #ffecb5; padding: 15px; margin: 20px 0; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="body">
        <div class="header">
            <h2 style="color: #007bff; margin: 0;">Security Notification</h2>
        </div>
        <div class="content">
            ${content}
        </div>
        <div class="footer">
            <p>&copy; ${new Date().getFullYear()} Security Center. All rights reserved.</p>
            <p>This is an automated system message. Please do not reply.</p>
        </div>
    </div>
</body>
</html>
`;

module.exports = {
  // 1. Registration Template
  registrationTemplate: (name, role) => getBaseTemplate(`
    <h3>Welcome, ${name}!</h3>
    <p>Your <strong>${role}</strong> account has been created successfully on our platform.</p>
    <p>You can now log in using your registered email address.</p>
    <a href="#" class="button">Log In to Your Account</a>
  `),

  // 2. Login Alert Template
  loginAlertTemplate: (name, role) => getBaseTemplate(`
    <h3>New Login Detected</h3>
    <p>Hello ${name},</p>
    <p>We detected a successful login to your <strong>${role}</strong> account just now.</p>
    <p>If this was not you, please secure your account immediately.</p>
  `),

  // 3. Account Locked Template (With Support Button)
  accountLockedTemplate: (isSupportLocked) => getBaseTemplate(`
    <h3 style="color: #dc3545;">Security Alert: Account Blocked</h3>
    <div class="warning-box">
        <p>Your account has been ${isSupportLocked ? '<strong>Permanently Locked</strong>' : '<strong>Temporarily Blocked</strong>'} due to multiple failed login attempts.</p>
    </div>
    <p>For your security, we have restricted access to prevent unauthorized entry.</p>
    <p>To regain access, please click the button below to contact our security team.</p>
    <a href="mailto:support@yourcompany.com" class="button" style="background-color: #dc3545;">Contact Security Team</a>
  `),

  // 4. OTP Template
  otpTemplate: (otp) => getBaseTemplate(`
    <h3>Your Unlock Code</h3>
    <p>You requested a code to unlock your account. Please use the following One-Time Password (OTP):</p>
    <div style="font-size: 32px; font-weight: bold; letter-spacing: 5px; text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px; margin: 20px 0;">
        ${otp}
    </div>
    <p>This code will expire in 10 minutes. <strong>Do not share this code with anyone.</strong></p>
  `),

  // 5. Account Unlocked Template
  accountUnlockedTemplate: () => getBaseTemplate(`
    <h3 style="color: #28a745;">Account Unlocked Successfully</h3>
    <p>Good news! Your account has been reviewed and successfully unlocked by our security team.</p>
    <p>You can now log in to your account using your credentials.</p>
    <a href="#" class="button" style="background-color: #28a745;">Log In Now</a>
  `),
};
