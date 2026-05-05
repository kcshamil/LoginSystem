const authTypeDefs = require("./auth/typeDefs");
const userTypeDefs = require("./user/typeDefs");
const authResolvers = require("./auth/resolvers");
const userResolvers = require("./user/resolvers");

/**
 * Root Schema Configuration
 * MNC Standard: Define empty base types and extend them in modules.
 */
const rootTypeDefs = `#graphql
  type Query {
    _empty: String
  }
  type Mutation {
    _empty: String
  }
`;

const typeDefs = [rootTypeDefs, authTypeDefs, userTypeDefs];

/**
 * Merge Resolvers
 * Combines all modular resolvers into a single object for Apollo Server.
 */
const resolvers = {
  Query: {
    ...userResolvers.Query,
  },
  Mutation: {
    ...authResolvers.Mutation,
  },
};

module.exports = { typeDefs, resolvers };
