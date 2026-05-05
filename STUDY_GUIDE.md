# 📚 Login System: Technical Study Guide (GraphQL Edition)

This guide explains the **GraphQL Architecture** and security logic of the Login System.

---

## 1. The Architecture (MNC Standard)
We use a **Single Endpoint** architecture powered by Apollo Server:
*   **Schema (`typeDefs.js`):** Defines the structure of data and available actions (Mutations/Queries).
*   **Resolvers (`resolvers.js`):** Acts as the bridge between the Schema and the Service Layer.
*   **Service Layer (`authService.js`):** Contains all the business logic, security checks, and database queries.
*   **Context (`index.js`):** A global middleware that verifies the JWT token for every request.

---

## 2. Core Security Logics (Simplified)

### A. Progressive Throttling
*   **Logic:** After 5 failures, the system doubles the wait time (30s, 60s, 120s...).
*   **Why:** To prevent high-speed brute-force attacks.

### B. Temporary Lockout
*   **Logic:** 10 failures in 15 minutes = 15-minute complete account block.

### C. Support Lock (Hard Lock)
*   **Logic:** 3 lockouts in 24 hours = Account disabled. User must use **OTP Recovery** or contact an Admin.

---

## 3. Account Recovery Flow (OTP Unlock)
1.  **Mutation `requestUnlockOtp`:** User requests a code via email.
2.  **Mutation `verifyUnlockOtp`:** User submits the 6-digit code.
3.  **Result:** System clears all security penalties and unlocks the account.

---

## 4. Example GraphQL Mutation (Login)
```graphql
mutation {
  login(email: "user@example.com", password: "password123") {
    statusCode
    message
    token
    retryAfterSeconds
  }
}
```

---

## 5. Middleware & RBAC
*   **Authentication:** Handled in the Apollo Context. If a token is valid, `context.user` is populated.
*   **Authorization (RBAC):** Inside resolvers, we check `context.user.role` to prevent non-admins from accessing sensitive mutations like `adminUnlockUser`.
