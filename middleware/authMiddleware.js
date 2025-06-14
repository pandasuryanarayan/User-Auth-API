// --- File: middleware/authMiddleware.js ---
// This middleware protects routes by verifying JWT
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import RevokedToken from '../models/RevokedToken.js';
import dotenv from 'dotenv';

// Load environment variables (necessary here too if this file is imported directly)
dotenv.config();

const protect = async (req, res, next) => {
  let token;

  // Read token from cookies instead of Authorization header
  token = req.cookies.accessToken;

  if (!token) {
    return res.status(401).json({ message: 'Not authorized, no access token found in cookies.' });
  }

  try {
    // NEW: Check if token is blacklisted
    const isRevoked = await RevokedToken.findOne({ token });
    if (isRevoked) {
      console.log(`Access token ${token} is blacklisted for user.`);
      // Clear the accessToken cookie if it's blacklisted
      res.clearCookie('accessToken');
      return res.status(401).json({ message: 'Access token has been revoked. Please log in again.' });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach user to the request object (without password or refresh token hash)
    req.user = await User.findById(decoded.id).select('-password -refreshTokenHash');
    
    if (!req.user) {
        // Token was valid but user no longer exists in DB
        // Clear the accessToken cookie as it's invalid for a non-existent user
        res.clearCookie('accessToken');
        return res.status(401).json({ message: 'Not authorized, user not found.' });
    }
    next();
  } catch (error) {
    console.error('Access token verification failed:', error.message);
    // Clear potentially expired/invalid access token cookie
    res.clearCookie('accessToken');
    // Do NOT clear refresh token here; auto-login will handle it if it needs refreshing.
    res.status(401).json({ message: 'Not authorized, access token invalid or expired. Please use auto-login or re-authenticate.' });
  }
};

export { protect }; // Exporting protect as a named export