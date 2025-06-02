# 🛠️ Express + MongoDB Backend API

A Node.js backend built using **Express**, **MongoDB (Mongoose)**, and **JWT authentication** with **cookie-based session support**, **subdomain CORS**, and user/shop management.

---

## 🔧 Tech Stack

- Node.js
- Express
- MongoDB + Mongoose
- JWT (JSON Web Tokens)
- Bcrypt (Password hashing)
- dotenv (Environment variables)
- CORS (with subdomain support)
- Cookie-parser

---

## 📁 Project Have a .env file .Example of


MONGODB_URI="mongodb+srv://username:password@cluster0.o1ht6xv.mongodb.net/Mern-Task?retryWrites=true&w=majority&appName=Cluster0"
JWT_SECRET="some thing you just added"
PORT=5000


## API Endpoints
Base URL: http://localhost:5000/api

🟢 POST /signup
Create a new user account with a unique username and at least 3 unique shop names.

🔐 POST /signin Authenticate user and set a secure JWT cookie.

🔐 GET /verify-token Verify the current JWT token and get user info. Helpful for subdomain apps.

🔐 GET /shop/:shopName Get shop info (name and owner) by shop name. Requires valid JWT.

🔒 POST /logout Logs the user out by clearing the JWT cookie.




## For Run project
npm run dev
