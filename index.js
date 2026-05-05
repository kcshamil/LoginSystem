require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { ApolloServer } = require("@apollo/server");
const { expressMiddleware } = require("@as-integrations/express4");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const { typeDefs, resolvers } = require("./graphql");

/**
 * Main application initialization.
 * Sets up the Express server, middleware, and the Apollo GraphQL server.
 */
const startServer = async () => {
  const app = express();
  const PORT = process.env.PORT || 4000;

  // Initialize Apollo GraphQL Server with our schema definitions
  const server = new ApolloServer({
    typeDefs,
    resolvers,
  });

  // Must start Apollo before applying middleware
  await server.start();

  // Security and Utility Middleware
  app.use(cors()); // Enable Cross-Origin Resource Sharing
  app.use(bodyParser.json()); // Parse incoming JSON requests
  app.use(express.urlencoded({ extended: true })); // Parse URL-encoded data
  app.use(express.static("public")); // Serve frontend assets (like unlock.html)

  /**
   * GraphQL Endpoint Configuration
   * Handles all API requests through a single /graphql route
   */
  app.use(
    "/graphql",
    expressMiddleware(server, {
      /**
       * Context function runs on every request.
       * It extracts the JWT token from the Authorization header and verifies the user.
       */
      context: async ({ req }) => {
        const authHeader = req.headers.authorization || "";
        const token = authHeader.split(" ")[1];
        let user = null;

        if (token) {
          try {
            // Verify the token using our secret key
            user = jwt.verify(token, process.env.JWT_SECRET);
          } catch (err) {
            // Silently fail if token is invalid; request proceeds as a guest
          }
        }

        return { req, user };
      },
    })
  );

  // Health check or default landing page
  app.get("/", (req, res) => {
    res.send("<h1>Login System API is Online</h1>");
  });

  // Start the HTTP server
  app.listen(PORT, () => {
    console.log(`Server ready at http://localhost:${PORT}`);
    console.log(`GraphQL Playground: http://localhost:${PORT}/graphql`);
  });
};

// Execute the server startup
startServer();