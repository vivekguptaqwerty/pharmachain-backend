import mongoose, { Schema, Document } from 'mongoose';

interface IAdmin extends Document {
  email: string;
  password: string;
  createdAt: Date;
}

const adminSchema = new Schema<IAdmin>({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

export const Admin = mongoose.model<IAdmin>('Admin', adminSchema);