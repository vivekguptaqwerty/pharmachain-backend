import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcryptjs';

interface IUser extends Document {
  name: string;
  phone: string;
  email: string;
  password: string;
  businessName: string;
  contactPerson?: string;
  address: string;
  role: string | null;
  status: string;
  documents: Record<string, string>;
  gstNumber?: string;
  drugLicenseNumber?: string;
  panNumber?: string;
  comparePassword(password: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>(
  {
    name: { type: String, required: true },
    phone: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true, select: false },
    businessName: { type: String, required: true },
    contactPerson: { type: String },
    address: { type: String, required: true },
    role: {
      type: String,
      enum: ['manufacturer', 'wholesaler', 'distributor', 'retailer', 'admin', null],
      default: null,
    },
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected'],
      default: 'pending',
    },
    documents: { type: Map, of: String, default: {} },
    gstNumber: { type: String },
    drugLicenseNumber: { type: String },
    panNumber: { type: String },
  },
  { timestamps: true }
);

userSchema.pre('save', async function (next) {
  // Only hash the password if it's not already hashed (i.e., doesn't start with $2b$)
  if (this.isModified('password') && !this.password.startsWith('$2b$')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

userSchema.methods.comparePassword = async function (password: string) {
  return bcrypt.compare(password, this.password);
};

// Define indexes explicitly
userSchema.index({ phone: 1 }, { unique: true });
userSchema.index({ email: 1 }, { unique: true });

export const User = mongoose.model<IUser>('User', userSchema);