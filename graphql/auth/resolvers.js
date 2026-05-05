const authService = require("../../services/authService");
const { getClientIp } = require("../../utils/helpers");

const resolvers = {
  Mutation: {
    register: async (_, { input }, context) => {
      try {
        const { name, email, password, role } = input;
        const requesterRole = context.user ? context.user.role : null;
        const result = await authService.registerUser(name, email, password, role, requesterRole);
        return { statusCode: 201, ...result };
      } catch (error) {
        return { statusCode: error.statusCode || 500, message: error.message };
      }
    },

    login: async (_, { email, password }, context) => {
      try {
        const ip = getClientIp(context.req);
        const userAgent = context.req.headers['user-agent'] || 'Unknown Device';
        const result = await authService.loginUser(email, password, ip, userAgent);
        return { statusCode: 200, ...result };
      } catch (error) {
        return { statusCode: error.statusCode || 500, message: error.message, retryAfterSeconds: error.retryAfterSeconds };
      }
    },

    requestUnlockOtp: async (_, { email }) => {
      try {
        const result = await authService.requestUnlockOtp(email);
        return { statusCode: 200, ...result };
      } catch (error) {
        return { statusCode: error.statusCode || 500, message: error.message };
      }
    },

    verifyUnlockOtp: async (_, { email, otp }) => {
      try {
        const result = await authService.verifyUnlockOtp(email, otp);
        return { statusCode: 200, ...result };
      } catch (error) {
        return { statusCode: error.statusCode || 500, message: error.message };
      }
    },

    adminUnlockUser: async (_, { targetEmail, targetRole }, context) => {
      try {
        if (!context.user || context.user.role !== 'admin') {
          return { statusCode: 403, message: "Administrative privileges required." };
        }
        const result = await authService.unlockUser(targetEmail, targetRole);
        return { statusCode: 200, ...result };
      } catch (error) {
        return { statusCode: error.statusCode || 500, message: error.message };
      }
    }
  }
};

module.exports = resolvers;
