const typeDefs = `#graphql
  enum UserRole {
    public
    subadmin
    admin
  }

  type AuthResponse {
    statusCode: Int!
    message: String!
    token: String
    retryAfterSeconds: Int
    contactSupport: String
    userId: Int
  }

  input RegisterInput {
    name: String!
    email: String!
    password: String!
    role: UserRole!
  }

  extend type Mutation {
    register(input: RegisterInput!): AuthResponse!
    login(email: String!, password: String!): AuthResponse!
    requestUnlockOtp(email: String!): AuthResponse!
    verifyUnlockOtp(email: String!, otp: String!): AuthResponse!
    adminUnlockUser(targetEmail: String!, targetRole: UserRole!): AuthResponse!
  }
`;

module.exports = typeDefs;
