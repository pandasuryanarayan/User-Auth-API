// --- File: models/User.js ---
// This defines the User schema and pre-save hooks for password hashing
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    refreshTokenHash: {
      type: String,
      required: false, // Not required at initial registration, but set on first login or specific flow
      unique: true, // Ensure uniqueness for direct lookup
      sparse: true // Allows null values, so unique constraint only applies to non-null values
    }
  },
  {
    timestamps: true, // Adds createdAt and updatedAt fields
  }
);

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Method to compare entered password with hashed password in DB
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Method to compare entered refresh token with hashed refresh token in DB
userSchema.methods.matchRefreshToken = async function (enteredToken) {
  if (!this.refreshTokenHash) {
    return false; // No refresh token stored
  }
  return await bcrypt.compare(enteredToken, this.refreshTokenHash);
};

const User = mongoose.model('User', userSchema);

export default User; // Exporting as default