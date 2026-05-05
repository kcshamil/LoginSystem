const resolvers = {
  Query: {
    me: async (_, __, context) => {
      if (!context.user) return null;
      return {
        id: context.user.id,
        email: context.user.email,
        role: context.user.role,
        name: context.user.name
      };
    },
  },
};

module.exports = resolvers;
