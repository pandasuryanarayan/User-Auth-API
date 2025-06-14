// --- File: server.js ---
// This is the main server file
import express from 'express';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import connectDB from './config/db.js'; // Added .js extension
import authRoutes from './routes/authRoutes.js'; // Added .js extension
import { protect } from './middleware/authMiddleware.js'; // Added .js extension

// Load environment variables
dotenv.config();

// Connect to MongoDB
connectDB();

const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Middleware to parse cookies
app.use(cookieParser());

// Catch-all for unknown routes (404 Not Found)
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found on this server.`
  });
});

// Generic error handler (handles all unhandled errors)
app.use((err, _req, res, _next) => {
  console.error('❌ Server Error:', err.stack);

  // Common known errors
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: 'Validation Error',
      errors: err.errors || err.message,
    });
  }

  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized',
      error: err.message,
    });
  }

  if (err.name === 'ForbiddenError') {
    return res.status(403).json({
      success: false,
      message: 'Forbidden',
      error: err.message
    });
  }

  if (err.name === 'NotFoundError') {
    return res.status(404).json({
      success: false,
      message: 'Not Found',
      error: err.message
    });
  }

  if (err.name === 'MethodNotAllowedError') {
    return res.status(405).json({
      success: false,
      message: 'Method Not Allowed',
      error: err.message
    });
  }

  if (err.name === 'RequestTimeoutError') {
    return res.status(408).json({
      success: false,
      message: 'Request Timeout',
      error: err.message
    });
  }

  if (err.name === 'ServiceUnavailableError') {
    return res.status(503).json({
      success: false,
      message: 'Service Unavailable',
      error: err.message
    });
  }

  if (err.name === 'TooManyRequestsError') {
    return res.status(429).json({
      success: false,
      message: 'Too Many Requests',
      error: err.message
    });
  }

  if (err.name === 'BadGatewayError') {
    return res.status(502).json({
      success: false,
      message: 'Bad Gateway',
      error: err.message
    });
  }

  // Default 500 handler
  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || 'Internal Server Error',
  });
});

// Basic home route
app.get('/', (_req, res) => {
  res.send('User Auth API is running...');
});

// Auth routes
app.use('/api/auth', authRoutes);

// Example of a protected route
app.get('/api/protected', protect, (req, res) => {
  // req.user will contain the user ID from the JWT payload
  res.json({ message: `Welcome, user ${req.user.id}! This is a protected route. All the protected work like profile change, etc will work now`, user: req.user });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log("User Auth API Service by Suryanarayan Panda");
});