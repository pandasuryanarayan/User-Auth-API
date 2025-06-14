// --- File: models/RevokedToken.js ---
// This defines the schema for blacklisting access tokens
import mongoose from 'mongoose';

const revokedTokenSchema = mongoose.Schema(
  {
    token: {
      type: String,
      required: true,
      unique: true,
      index: true // Index for faster lookups
    },
    expiresAt: {
      type: Date,
      required: true,
      expires: 0 // MongoDB TTL index: document expires after 'expiresAt' date
    }
  },
  {
    timestamps: true // To track when it was added
  }
);

const RevokedToken = mongoose.model('RevokedToken', revokedTokenSchema);

export default RevokedToken;