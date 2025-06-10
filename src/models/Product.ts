import mongoose, { Schema, Document } from 'mongoose';

interface IProduct extends Document {
  name: string;
  batchNumber: string;
  expiryDate: Date;
  price: number;
  quantity: number;
  minQuantity: number;
  category: string;
  description?: string;
  image?: string;
  userId: mongoose.Types.ObjectId;
  role: string;
  manufacturerId?: mongoose.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

const productSchema = new Schema<IProduct>(
  {
    name: { type: String, required: true },
    batchNumber: { type: String, required: true },
    expiryDate: { type: Date, required: true },
    price: { type: Number, required: true, min: 0 },
    quantity: { type: Number, required: true, min: 0 },
    minQuantity: { type: Number, required: true, min: 1, default: 1 },
    category: {
      type: String,
      enum: ['Analgesic', 'Antibiotic', 'Antidiabetic', 'Vitamin', 'Cardiovascular', 'Respiratory', 'Gastrointestinal', 'Other'],
      required: true,
    },
    description: { type: String },
    image: { type: String },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    role: { type: String, enum: ['manufacturer', 'wholesaler', 'distributor'], required: true },
    manufacturerId: { type: Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: true }
);

// Define indexes explicitly
productSchema.index({ userId: 1 });
productSchema.index({ role: 1 });
productSchema.index({ batchNumber: 1 }, { unique: true });
productSchema.index({ manufacturerId: 1 });

export const Product = mongoose.model<IProduct>('Product', productSchema);