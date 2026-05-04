const getTableByRole = (role) => {
  if (role === "public") return "public_users";
  if (role === "subadmin") return "sub_admins";
  if (role === "admin") return "admins";
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

const generateOTP = () => {
  // Generates a random 6-digit number string
  return Math.floor(100000 + Math.random() * 900000).toString();
};

module.exports = {
  getTableByRole,
  getClientIp,
  generateOTP
};
