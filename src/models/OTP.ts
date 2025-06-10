import mongoose, { Schema, Document } from 'mongoose';

interface IOTP extends Document {
  email: string;
  otp: string;
  expiresAt: Date;
  verified: boolean;
  type: 'signup' | 'password_reset';
}

const otpSchema = new Schema<IOTP>(
  {
    email: { type: String, required: true, index: true },
    otp: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    verified: { type: Boolean, default: false },
    type: { type: String, enum: ['signup', 'password_reset'], required: true },
  },
  { timestamps: true }
);

// TTL index to auto-delete expired OTPs after 10 minutes
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const OTP = mongoose.model<IOTP>('OTP', otpSchema);