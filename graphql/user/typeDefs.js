const typeDefs = `#graphql
  type User {
    id: ID!
    email: String!
    name: String!
    role: UserRole!
  }

  extend type Query {
    me: User
  }
`;

module.exports = typeDefs;
