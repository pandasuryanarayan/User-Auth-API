// --- File: routes/authRoutes.js ---
// This defines the API routes for authentication
import express from 'express';
import { registerUser, loginUser, autoLoginUser, logoutUser } from '../controllers/authController.js';
import { body } from 'express-validator';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

// Registration route with validation
router.post(
  '/register',
  [
    body('username', 'Username is required').notEmpty(),
    body('email', 'Please include a valid email').isEmail(),
    body('password', 'Password must be at least 6 characters').isLength({ min: 6 }),
  ],
  registerUser
);

// Login route with validation
router.post(
  '/login',
  [
    body('email', 'Please include a valid email').isEmail(),
    body('password', 'Password is required').notEmpty(),
  ],
  loginUser
);

// Auto-Login route using refresh token
router.post('/auto-login', autoLoginUser);

// Logout route - protected to invalidate refresh token
router.post('/logout', protect, logoutUser);

export default router; // Exporting as default