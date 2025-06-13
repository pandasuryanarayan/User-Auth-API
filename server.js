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

// Basic home route
app.get('/', (req, res) => {
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