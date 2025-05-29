# Authix Capstone Project (Insecure Edition)

This is the **intentionally insecure** version of the Authix full-stack web application, created for penetration testing and security education.

## 🔧 Stack

* **Frontend**: SvelteKit + TypeScript
* **Backend**: Express.js + Prisma ORM + Supabase Postgres
* **Database**: Supabase (hosted PostgreSQL)

## ⚠️ Insecurity Features (Purposefully Left Vulnerable)

* No input validation (susceptible to SQLi and XSS)
* No real authentication — fake JWT token `Bearer fake-jwt-token` used
* No CSRF protection
* No rate limiting or brute-force defense
* No HTTPS enforcement
* No environment secret protection in production

## 🧪 Pen Test Attack Surfaces

* `POST /auth/login` — Test SQLi, brute-force
* `GET /auth/me` — Bypass logic, spoof tokens
* User-facing forms — Stored and reflected XSS
* Route params (e.g., `/users/:id`) — IDOR (insecure direct object reference)
* Session/state-based attacks — No auth state validation

## 📁 Folder Structure

```
/authix
├── backend
│   ├── src
│   │   ├── routes
│   │   ├── controllers
│   │   ├── prisma
│   │   └── app.ts
│   ├── prisma
│   │   └── schema.prisma
│   ├── .env
│   ├── tsconfig.json
│   └── package.json
├── frontend
│   ├── src
│   │   └── routes
│   │       └── +layout.svelte
│   ├── .env
│   └── package.json
```

## 🚀 Running Locally

1. **Start the backend**:

   ```bash
   cd backend
   npm install
   npm run dev
   ```
2. **Start the frontend**:

   ```bash
   cd frontend
   npm install
   npm run dev
   ```

## 🛑 Important

**This app is insecure by design.** Do not deploy this version in a production environment.

---

## ✅ Goal

Use this version to practice real-world attacks and assess vulnerabilities before implementing secure patches in later stages.
