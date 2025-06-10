
import mongoose, { Schema, Document } from 'mongoose';

interface IOrderItem {
  productId: mongoose.Types.ObjectId;
  name: string;
  quantity: number;
  price: number;
}

interface IShippingInfo {
  name: string;
  phone: string;
  address: string;
  city: string;
  pincode: string;
  state: string;
}

interface IOrder extends Document {
  userId: mongoose.Types.ObjectId;
  buyerId: mongoose.Types.ObjectId;
  sellerId: mongoose.Types.ObjectId;
  items: IOrderItem[];
  totalAmount: number;
  totalQuantity: number;
  shippingInfo: IShippingInfo;
  status: string;
  paymentStatus: 'Pending' | 'Paid' | 'Failed';
  paymentMethod: string;
  transactionId?: string;
  orderId: string;
  trackingStatus?: string[];
  createdAt: Date;
  updatedAt: Date;
}

const orderSchema = new Schema<IOrder>(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    buyerId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    sellerId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    items: [
      {
        productId: { type: Schema.Types.ObjectId, ref: 'Product', required: true },
        name: { type: String, required: true },
        quantity: { type: Number, required: true },
        price: { type: Number, required: true },
      },
    ],
    totalAmount: { type: Number, required: true },
    totalQuantity: { type: Number, required: true },
    shippingInfo: {
      name: { type: String, required: true },
      phone: { type: String, required: true },
      address: { type: String, required: true },
      city: { type: String, required: true },
      pincode: { type: String, required: true },
      state: { type: String, required: true },
    },
    status: {
      type: String,
      enum: ['Pending', 'Approved', 'Shipped', 'Delivered', 'Cancelled'],
      default: 'Pending',
    },
    paymentStatus: {
      type: String,
      enum: ['Pending', 'Paid', 'Pending'],
      default: 'Pending',
    },
    paymentMethod: { type: String, required: true },
    transactionId: { type: String },
    orderId: { type: String, required: true },
    trackingStatus: [{ type: String }],
  },
  { timestamps: true }
);

orderSchema.index({ userId: 1 });
orderSchema.index({ buyerId: 1 });
orderSchema.index({ sellerId: 1 });

export const Order = mongoose.model<IOrder>('Order', orderSchema);
