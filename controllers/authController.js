// --- File: controllers/authController.js ---
// This contains the logic for registration, login, and logout
import { validationResult } from 'express-validator';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import RevokedToken from '../models/RevokedToken.js';
import dotenv from 'dotenv';
import crypto from 'crypto'; // For generating cryptographically secure random strings
import bcrypt from 'bcryptjs'; // For hashing the refresh token

// Load environment variables (necessary here too if this file is imported directly)
dotenv.config();

// Define cookie options for HttpOnly, Secure, and SameSite
const cookieOptions = {
  httpOnly: true,
  secure: true, // Only true in production over HTTPS
  sameSite: 'None', // Protects against CSRF attacks. Can be 'Strict' for more security or 'None' with secure:true for cross-site
  maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days (for refresh token)
};

// Generate JWT token
const generateAccessToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '10m', // Token expires in 10 minutes
  });
};

// Generate a secure random string for the refresh token
const generateRefreshToken = () => {
  return crypto.randomBytes(64).toString('hex'); // 64 bytes = 128 hex characters
};

// @desc    Register a new user
// @route   POST /api/auth/register
// @access  Public
const registerUser = async (req, res) => {
  // Validate request body
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, email, password } = req.body;

  try {
    // Check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Generate and hash refresh token
    const refreshToken = generateRefreshToken();
    const salt = await bcrypt.genSalt(10);
    const refreshTokenHash = await bcrypt.hash(refreshToken, salt);

    // Create new user
    const user = await User.create({
      username,
      email,
      password,
      refreshTokenHash // Store the hashed refresh token
    });

    if (user) {
      // Generate tokens
      const accessToken = generateAccessToken(user._id);

      // Set tokens in HTTP-only cookies
      res.cookie('accessToken', accessToken, { ...cookieOptions, maxAge: 10 * 60 * 1000 }); // 1 hour for access token
      res.cookie('refreshToken', refreshToken, cookieOptions); // 7 days for refresh token

      res.status(201).json({
        message: 'User registered successfully',
        _id: user._id,
        username: user.username,
        email: user.email,
        accessToken: accessToken, // Renamed to accessToken for clarity
        refreshToken: refreshToken // Send the plain refresh token to the client
      });
    } else {
      res.status(400).json({ message: 'Invalid user data' });
    }
  } catch (error) {
    console.error(error);
    // Handle potential duplicate refreshTokenHash error
    if (error.code === 11000 && error.keyPattern && error.keyPattern.refreshTokenHash) {
      return res.status(409).json({ message: 'A unique token generation conflict occurred. Please try again.' });
    }
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Authenticate user & get token
// @route   POST /api/auth/login
// @access  Public
const loginUser = async (req, res) => {
  // Validate request body
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    // Check if user exists
    const user = await User.findOne({ email });

    // Check if user exists and password matches
    if (user && (await user.matchPassword(password))) {
      // Generate and hash a NEW refresh token upon successful login
      const newRefreshToken = generateRefreshToken();
      const salt = await bcrypt.genSalt(10);
      const newRefreshTokenHash = await bcrypt.hash(newRefreshToken, salt);

      // Update user with the new refresh token hash
      user.refreshTokenHash = newRefreshTokenHash;
      await user.save(); // Save the updated user document

      // Generate new access token
      const newAccessToken = generateAccessToken(user._id);

      // Set new tokens in HTTP-only cookies
      res.cookie('accessToken', newAccessToken, { ...cookieOptions, maxAge: 10 * 60 * 1000 });
      res.cookie('refreshToken', newRefreshToken, cookieOptions);

      res.json({
        message: 'Logged in successfully',
        _id: user._id,
        username: user.username,
        email: user.email,
        accessToken: newAccessToken, // Renamed to accessToken
        refreshToken: newRefreshToken // Send the new refresh token to the client
      });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Auto-login user using refresh token
// @route   POST /api/auth/auto-login
// @access  Public
/*
  This is the auto-login functionality demonstrating the the auto login after the user registers himself 
  without needing to login again manually.
  This is one time way. After logout it will not work and user will have to login again.
*/
const autoLoginUser = async (req, res) => {
  const { refreshToken } = req.cookies; // Get refresh token from cookie

  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token is required' });
  }

  try {
    // Find user by comparing the provided plain refresh token with the hashed ones in DB
    // Since refreshTokenHash is unique and sparse, we can potentially find it directly
    // This requires iterating through users and comparing hashes. For performance,
    // in a very large DB, you might use a dedicated refresh token store or a more complex lookup.
    // For now, we'll iterate and compare.
    const users = await User.find({}); // Fetch all users (not ideal for large scale, but demonstrates comparison)
    let userFound = null;

    for (const user of users) {
      if (user.refreshTokenHash && (await user.matchRefreshToken(refreshToken))) {
        userFound = user;
        break;
      }
    }

    if (!userFound) {
      // If refresh token is invalid or expired, clear it from client
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      return res.status(401).json({ message: 'Invalid or expired refresh token' });
    }

    // Generate NEW access token and NEW refresh token
    const newAccessToken = generateAccessToken(userFound._id);
    const newRefreshToken = generateRefreshToken();
    const salt = await bcrypt.genSalt(10);
    const newRefreshTokenHash = await bcrypt.hash(newRefreshToken, salt);

    // Update user with the new refresh token hash in DB
    userFound.refreshTokenHash = newRefreshTokenHash;
    await userFound.save();

    // Set new tokens in HTTP-only cookies
    res.cookie('accessToken', newAccessToken, { ...cookieOptions, maxAge: 10 * 60 * 1000 });
    res.cookie('refreshToken', newRefreshToken, cookieOptions);

    // Refresh token is valid, issue a new access token
    res.json({
      message: 'Auto-login successful.',
      _id: userFound._id,
      username: userFound.username,
      email: userFound.email,
      accessToken: newAccessToken, // Renamed to accessToken
      refreshToken: newRefreshToken // Send the new refresh token to the client
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};

// @desc    Logout user (client-side token removal and server-side refresh token/access token invalidation)
// @route   POST /api/auth/logout
// @access  Private
const logoutUser = async (req, res) => {
  const accessToken = req.cookies.accessToken; // Get the current access token from cookie

  if (!req.user || !req.user.id) {
    console.error('Logout: req.user or req.user.id is missing.');
    // Clear cookies even if user ID isn't directly available from token
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    return res.status(401).json({ message: 'Not authorized or user information missing for logout. Cookies cleared.' });
  }

  console.log(`Attempting to logout user ID: ${req.user.id}`);

  try {
    // 1. Invalidate refreshTokenHash in the database
    const userUpdateResult = await User.findByIdAndUpdate(
      req.user.id,
      { $unset: { refreshTokenHash: 1 } },
      { new: true }
    );

    // 2. Blacklist the current accessToken
    if (accessToken) {
      const decoded = jwt.decode(accessToken);
      if (decoded && decoded.exp) {
        const expiresAt = new Date(decoded.exp * 1000); // JWT exp is in seconds, convert to milliseconds
        await RevokedToken.create({ token: accessToken, expiresAt });
        console.log(`Access token blacklisted for user ID: ${req.user.id}`);
      } else {
        console.warn('Could not decode access token or extract expiry for blacklisting:', accessToken);
      }
    } else {
      console.log('No access token found in cookies to blacklist.');
    }

    // 3. Clear tokens from HTTP-only cookies
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    if (userUpdateResult) {
      console.log(`User ID: ${req.user.id} refresh token hash successfully invalidated and cookies cleared.`);
      res.json({ message: 'User logged out successfully and all tokens invalidated.' });
    } else {
      console.log(`User ID: ${req.user.id} not found for logout (perhaps already logged out or invalid ID). Cookies cleared.`);
      res.status(404).json({ message: 'User not found or refresh token already invalidated. Cookies cleared.' });
    }
  } catch (error) {
    console.error(`Error during logout for user ID ${req.user.id}:`, error);
    res.status(500).json({ message: 'Server error during logout.' });
  }
};

export {
  registerUser,
  loginUser,
  autoLoginUser,
  logoutUser,
};