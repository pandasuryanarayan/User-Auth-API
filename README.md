# User Authentication API with JWT

## Overview

This project provides a secure and robust user authentication API built with Node.js, Express, and MongoDB, leveraging JSON Web Tokens (JWT) for stateless authentication. It includes functionalities for user registration, login, and a protected route accessible only to authenticated users. Input validation is handled using `express-validator` to ensure data integrity and security. Here token is revoked on logout or expiry of token and all protected routes are protected.

---

## Features

- **User Registration**: Allows new users to create accounts with unique usernames and emails. Passwords are securely hashed using `bcryptjs` before storage.
- **User Login**: Authenticates existing users based on their email and password. Upon successful login, a JSON Web Token (JWT) is issued.
- **JWT-Based Authentication**: Utilizes JWTs for secure, stateless authentication, allowing clients to access protected resources by sending the token.
- **Protected Routes**: Demonstrates how to secure API endpoints, ensuring only authenticated users with valid tokens can access them.
- **Input Validation**: Implements `express-validator` to validate user input for registration and login, enhancing security and data quality.
- **MongoDB Integration**: Uses Mongoose for seamless interaction with a MongoDB database for user data storage.
- **Environment Variables**: Configures sensitive information (like MongoDB URI and JWT Secret) using `.env` files for secure deployment.
- **ES Modules (ESM)**: Developed using modern JavaScript ES module syntax (`import/export`).

---

## Project Structure

```
user-auth-api/
├── .env
├── package.json
├── server.js               # Main application entry point
├── config/
│   └── db.js               # MongoDB connection setup
├── controllers/
│   └── authController.js   # Logic for register, login, logout
├── middleware/
│   └── authMiddleware.js   # JWT verification middleware
├── models/
│   └── User.js             # Mongoose schema for User
│   └── RevokedToken.js     # Mongoose schema for Revoked Token
└── routes/
    └── authRoutes.js       # Routes for authentication
```

## Technologies Used

- Node.js
- Express.js
- MongoDB
- Mongoose
- bcryptjs
- jsonwebtoken (JWT)
- express-validator
- dotenv
- nodemon
- cookie-parser
- crypto

---

## Setup and Installation

### Prerequisites

Ensure the following software is installed:

- **Node.js**: Version 22.x or later (LTS recommended)
  Download: [https://nodejs.org/](https://nodejs.org/) 
- **npm**: Comes bundled with Node.js
- MongoDB instance (local or MongoDB Atlas)

Verify installation:
```bash
node -v
npm -v
````

### Installation

1. Clone the repository or set up the files manually:

A
```bash
git clone <your-repo-url>
cd user-auth-api
````
B
```
Download all available files Manually.
```

2. Install dependencies:

```bash
npm install
```

3. Create a `.env` file in the root directory and add:

```env
MONGO_URI=mongodb://localhost:27017/userauthapi
JWT_SECRET=your_super_secret_jwt_key_here_make_it_long_and_random
PORT=5000
```

---

## Running the Application

### Development Mode

```bash
npm run dev
```

Uses `nodemon` to restart on changes.

### Production Mode

```bash
npm start
```

The server will run on `http://localhost:5000` or your configured `PORT`.

---

## API Endpoints

All routes are prefixed with `/api/auth`.

### 1. Register User

* **URL**: `/api/auth/register`
* **Method**: `POST`
* **Access**: Public
* **Request Body**:

```json
{
  "username": "john_doe",
  "email": "john.doe@example.com",
  "password": "securepassword123"
}
```

* **Success Response**:

```json
{
  "message": "User registered successfully",
  "_id": "60c72b2f9b1e8b001c8e1e7a",
  "username": "john_doe",
  "email": "john.doe@example.com",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

* **Error Response**:

```json
{
  "errors": [
    {
      "msg": "Username is required",
      "param": "username",
      "location": "body"
    }
  ]
}
```

or

```json
{
  "message": "User already exists"
}
```

---

### 2. Login User

* **URL**: `/api/auth/login`
* **Method**: `POST`
* **Access**: Public
* **Request Body**:

```json
{
  "email": "john.doe@example.com",
  "password": "securepassword123"
}
```

* **Success Response**:

```json
{
  "message": "Logged in successfully",
  "_id": "60c72b2f9b1e8b001c8e1e7a",
  "username": "john_doe",
  "email": "john.doe@example.com",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6Ik......",
}
```

* **Error Response**:

```json
{
  "message": "Invalid email or password"
}
```
---
### 4. Auto-Login User API

#### Overview

This endpoint allows clients to obtain a new access token using a previously issued refresh token. This mechanism supports session continuity without requiring the user to repeatedly log in with their email and password.

- **URL:** `/api/auth/auto-login`
- **Method:** `POST`
- **Access:** Public
- **Content-Type:** `application/json`

### Description

Clients can send a valid `refreshToken` to receive a new `accessToken` for accessing protected routes. This is typically used to keep users logged in between sessions (e.g., when a browser or app is reopened).

---

### Request Body

```json
{
  "refreshToken": "a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
}
````

* `refreshToken` (string): A valid refresh token issued during login. It must not be expired or blacklisted.

---

### Success Response

**Status Code:** `200 OK`

```json
{
  "message": "Auto-login successful",
  "_id": "60c72b2f9b1e8b001c8e1e7a",
  "username": "john_doe",
  "email": "john.doe@example.com",
  "accessToken": "eciOiJIyJhbGUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eciOiJIyJhbGUzI1NiIsInR5cCI6IkpXV...."
}
```
---

### 4. Logout User

* **URL**: `/api/auth/logout`

* **Method**: `GET`

* **Access**: Public

* **Description**: This will clear the token from client side and server side and thus destroying the session of login.

* **Response**:

```json
{
    "message": "User logged out successfully and refresh token invalidated."
}
```
---

### Error Responses

#### 🔸 Invalid or Expired Token

**Status Code:** `401 Unauthorized`

```json
{
    "message": "Not authorized, no access token found in cookies."
}
```

---

### Notes

* This endpoint assumes you are using **access token + refresh token** flow.
* The `accessToken` returned should be stored securely on the client (e.g., in memory or HTTP-only cookies).
* Do **not** expose or store refresh tokens in insecure locations like `localStorage`.
* If the refresh token is compromised or blacklisted, auto-login will fail, prompting a full login.

---

### Example Use Case

1. User logs in and receives:

   * `accessToken` (short-lived)
   * `refreshToken` (long-lived, stored securely)
2. Later, when `accessToken` expires:

   * Client sends `refreshToken` to `/api/auth/auto-login`
   * Server verifies and issues a new `accessToken`
---

### 5. Protected Route Example

* **URL**: `/api/protected`
* **Method**: `GET`
* **Access**: Private (Requires JWT) in cookies

* **Success Response**:

```json
{
    "message": "Welcome, user 684ca07fc64ca3609c451788! This is a protected route. All the protected work like profile change, etc will work now",
    "user": {
        "_id": "684ca07fc64ca3609c451788",
        "username": "john_doe",
        "email": "john.doe@example.com",
        "createdAt": "2025-06-13T22:04:47.562Z",
        "updatedAt": "2025-06-13T22:19:19.051Z",
        "__v": 0
    }
}
```

* **Error Responses**:

**Status Code:** `401 Unauthorized`
```json
{
    "message": "Not authorized, no access token found in cookies."
}
```
---

---

## Support

If you encounter any issues, open an issue on the GitHub repo or contact **Suryanarayan Panda** directly.

---

## License

This project is licensed under the **ISC License**. See the [LICENSE](./LICENSE) file for more details.

## Acknowledgments

This project utilizes the following open-source technologies to build the blog CRUD backend API:

- **[Express.js](https://expressjs.com/)**: A fast, unopinionated, minimalist web framework used for building the server and defining API routes.

- **[jsonwebtoken (JWT)](https://github.com/auth0/node-jsonwebtoken)**: A library for implementing JSON Web Token (JWT) based authentication, securing protected routes.