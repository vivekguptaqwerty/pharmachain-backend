import { Request, Response } from 'express';
import { Product } from '../models/Product';
import { Order } from '../models/Order';
import { User } from '../models/User';
import { logger } from '../config/logger';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import path from 'path';
import * as fs from 'fs';
import multer from 'multer';
import Razorpay from 'razorpay';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import PDFDocument from 'pdfkit';

interface AuthRequest extends Request {
  user?: { userId: string; role: string };
}

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder',
  key_secret: process.env.RAZORPAY_KEY_SECRET || 'placeholder_secret',
});

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587'),
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const sendOrderEmails = async (order: any, buyer: any, seller: any) => {
  const doc = new PDFDocument();
  const invoicePath = path.join(__dirname, '..', 'Uploads', `invoice_${order.orderId}.pdf`);
  const stream = fs.createWriteStream(invoicePath);
  doc.pipe(stream);

  doc.fontSize(20).text('PharmaChain Invoice', { align: 'center' });
  doc.moveDown();
  doc.fontSize(12).text(`Order ID: ${order.orderId}`);
  doc.text(`Date: ${new Date(order.createdAt).toLocaleDateString()}`);
  doc.text(`Buyer: ${buyer.businessName}`);
  doc.text(`Seller: ${seller.businessName}`);
  doc.moveDown();

  doc.text('Items:', { underline: true });
  order.items.forEach((item: any) => {
    doc.text(`${item.name} - Qty: ${item.quantity} - Price: ₹${item.price}`);
  });
  doc.moveDown();
  doc.text(`Total: ₹${order.totalAmount}`, { align: 'right' });

  doc.text('Shipping:', { underline: true });
  doc.text(`Name: ${order.shippingInfo.name}`);
  doc.text(`Address: ${order.shippingInfo.address}, ${order.shippingInfo.city}, ${order.shippingInfo.state} ${order.shippingInfo.pincode}`);
  doc.text(`Phone: ${order.shippingInfo.phone}`);

  doc.end();

  await new Promise<void>((resolve) => stream.on('finish', () => resolve()));

  const mailOptions = (to: string, subject: string, text: string, isBuyer: boolean) => ({
    from: process.env.SMTP_USER,
    to,
    subject,
    text,
    attachments: isBuyer ? [{ filename: `invoice_${order.orderId}.pdf`, path: invoicePath }] : [],
  });

  await transporter.sendMail(
    mailOptions(
      buyer.email,
      'PharmaChain Order Confirmation',
      `Dear ${buyer.businessName},\n\nYour order ${order.orderId} has been placed successfully.\nTotal: ₹${order.totalAmount}\n\nSee attached invoice.\n\nThank you,\nPharmaChain Team`,
      true
    )
  );

  await transporter.sendMail(
    mailOptions(
      seller.email,
      'PharmaChain New Order Received',
      `Dear ${seller.businessName},\n\nYou have received a new order ${order.orderId} from ${buyer.businessName}.\nTotal: ₹${order.totalAmount}\n\nPlease process the order.\n\nThank you,\nPharmaChain Team`,
      false
    )
  );
};

export const getDashboard = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);

    const [totalOrdersPlaced, ordersReceived, activeProducts, monthlyRevenue, recentOrders] = await Promise.all([
      Order.countDocuments({ buyerId: userId }),
      Order.countDocuments({ sellerId: userId }),
      Product.countDocuments({ userId, quantity: { $gt: 0 } }),
      Order.aggregate([
        { $match: { sellerId: new mongoose.Types.ObjectId(userId), status: 'Delivered', createdAt: { $gte: startOfMonth } } },
        { $group: { _id: null, total: { $sum: '$totalAmount' } } },
      ]),
      Order.find({ sellerId: userId })
        .populate('buyerId', 'businessName')
        .sort({ createdAt: -1 })
        .limit(5)
        .lean(),
    ]);

    res.status(200).json({
      totalOrdersPlaced,
      ordersReceived,
      activeProducts,
      monthlyRevenue: Array.isArray(monthlyRevenue) && monthlyRevenue.length > 0 ? monthlyRevenue[0].total : 0,
      recentOrders: recentOrders.map(order => ({
        _id: order._id,
        buyerName: typeof order.buyerId === 'object' && order.buyerId !== null && 'businessName' in order.buyerId
          ? (order.buyerId as any).businessName
          : '-',
        orderDate: order.createdAt,
        totalQuantity: order.totalQuantity,
        status: order.status,
        totalAmount: order.totalAmount,
      })),
    });
  } catch (error) {
    logger.error('Dashboard error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const addProduct = async (req: AuthRequest, res: Response): Promise<void> => {
  const { productName, batchNumber, expiryDate, price, minQuantity, quantity, category, description, manufacturer } = req.body;
  const file = req.file; // Use req.file directly
  const user = req.user;

  if (!user?.userId || !user?.role) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }
  const { userId, role } = user;

  try {
    // Validate required fields
    if (!productName || !batchNumber || !expiryDate || !price || !minQuantity || !category) {
      res.status(400).json({ message: 'All required fields must be provided' });
      return;
    }

    // Validate minQuantity and quantity
    const parsedMinQuantity = parseInt(minQuantity);
    const parsedQuantity = parseInt(quantity);
    if (isNaN(parsedMinQuantity) || parsedMinQuantity < 1) {
      res.status(400).json({ message: 'Minimum quantity must be at least 1' });
      return;
    }
    if (isNaN(parsedQuantity) || parsedQuantity < parsedMinQuantity) {
      res.status(400).json({ message: 'Quantity must be at least equal to minimum quantity' });
      return;
    }

    let manufacturerId: mongoose.Types.ObjectId | undefined;
    if (role !== 'manufacturer' && manufacturer) {
      const manufacturerUser = await User.findOne({ _id: manufacturer, role: 'manufacturer' });
      if (!manufacturerUser) {
        res.status(400).json({ message: 'Invalid manufacturer' });
        return;
      }
      manufacturerId = manufacturerUser._id as mongoose.Types.ObjectId;
    }

    let imagePath: string | undefined;
    if (file) {
      imagePath = `/Uploads/${file.filename}`;
    }

    const product = new Product({
      name: productName,
      batchNumber,
      expiryDate,
      price: parseFloat(price),
      quantity: parsedQuantity,
      minQuantity: parsedMinQuantity,
      category,
      description,
      image: imagePath,
      userId,
      role,
      manufacturerId,
    });

    await product.save();
    logger.info(`Product added by user ${userId}: ${productName}`);
    res.status(201).json(product);
  } catch (error: any) {
    logger.error('Add product error:', { error: error.message, stack: error.stack });
    res.status(500).json({ message: 'Server error' });
  }
};

export const getProducts = async (req: AuthRequest, res: Response): Promise<void> => {
  const { search = '', page = '1', limit = '10' } = req.query;
  const userId = req.user?.userId;

  if (!userId) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  try {
    const pageNum = parseInt(page as string);
    const limitNum = parseInt(limit as string);
    const skip = (pageNum - 1) * limitNum;

    const query = {
      userId,
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { category: { $regex: search, $options: 'i' } },
      ],
    };

    const [products, total] = await Promise.all([
      Product.find(query)
        .skip(skip)
        .limit(limitNum)
        .lean(),
      Product.countDocuments(query),
    ]);

    res.status(200).json({
      products: products.map(p => ({
        ...p,
        status: p.quantity === 0 ? 'Out of Stock' : p.quantity <= 50 ? 'LowStock' : 'InStock',
      })),
      total,
    });
  } catch (error) {
    logger.error('Get products error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const updateProduct = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const userId = req.user?.userId;
    const productId = req.params.id;
    if (!userId) {
      res.status(401).json({ message: 'Product not authorized' });
      return;
    }

    const {
      productName,
      batchNumber,
      expiryDate,
      price,
      minQuantity,
      quantity,
      category,
      description,
      manufacturer,
    } = req.body;

    const product = await Product.findOne({ _id: productId, userId });
    if (!product) {
      res.status(404).json({ message: 'Product not found or unauthorized' });
      return;
    }

    const parsedMinQuantity = minQuantity ? parseInt(minQuantity) : product.minQuantity;
    const parsedQuantity = quantity ? parseInt(quantity) : product.quantity;

    if (parsedMinQuantity < 1) {
      res.status(400).json({ message: 'Minimum quantity must be at least 1' });
      return;
    }
    if (parsedQuantity < parsedMinQuantity) {
      res.status(400).json({ message: 'Quantity must be at least equal to minimum quantity' });
      return;
    }

    const updateData: any = {
      name: productName || product.name,
      batchNumber: batchNumber || product.batchNumber,
      expiryDate: expiryDate || product.expiryDate,
      price: price ? parseFloat(price) : product.price,
      quantity: parsedQuantity,
      minQuantity: parsedMinQuantity,
      category: category || product.category,
      description: description !== undefined ? description : product.description,
    };

    if (req.file) {
      if (product.image) {
        const oldImagePath = path.join(__dirname, '..', 'Uploads', product.image.replace('/Uploads/', ''));
        if (fs.existsSync(oldImagePath)) {
          fs.unlinkSync(oldImagePath);
        }
      }
      updateData.image = `/Uploads/${req.file.filename}`;
    }

    if (manufacturer && req.user?.role !== 'manufacturer') {
      updateData.manufacturerId = manufacturer;
    }

    const updatedProduct = await Product.findByIdAndUpdate(
      productId,
      { $set: updateData },
      { new: true }
    );

    res.status(200).json({ message: 'Product updated successfully', product: updatedProduct });
  } catch (error: any) {
    logger.error('Update product error:', error);
    res.status(400).json({ message: error.message });
  }
};

export const deleteProduct = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const userId = req.user?.userId;
    const productId = req.params.id;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const product = await Product.findOne({ _id: productId, userId });
    if (!product) {
      res.status(404).json({ message: 'Product not found or unauthorized' });
      return;
    }

    if (product.image) {
      const imagePath = path.join(__dirname, '..', 'Uploads', product.image.replace('/Uploads/', ''));
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }

    await Product.findByIdAndDelete(productId);

    res.status(200).json({ message: 'Product deleted successfully' });
  } catch (error: any) {
    logger.error('Delete product error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const getOrders = async (req: AuthRequest, res: Response): Promise<void> => {
  const { status = '', page = '1', limit = '10' } = req.query;
  const userId = req.user?.userId;

  if (!userId) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  try {
    const pageNum = parseInt(page as string);
    const limitNum = parseInt(limit as string);
    const skip = (pageNum - 1) * limitNum;

    const query: any = { sellerId: userId };
    if (status) query.status = status;

    const [orders, total] = await Promise.all([
      Order.find(query)
        .populate({ path: 'buyerId', select: 'businessName contactPerson', model: 'User' })
        .skip(skip)
        .limit(limitNum)
        .lean({ virtuals: true }),
      Order.countDocuments(query),
    ]);

    res.status(200).json({
      orders: orders.map(o => ({
        ...o,
        buyer: typeof o.buyerId === 'object' && o.buyerId !== null && 'businessName' in o.buyerId
          ? (o.buyerId as any).businessName
          : '-',
        contact: typeof o.buyerId === 'object' && o.buyerId !== null && 'contactPerson' in o.buyerId
          ? (o.buyerId as any).contactPerson
          : '-',
      })),
      total,
    });
  } catch (error) {
    logger.error('Get orders error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const updateOrderStatus = async (req: AuthRequest, res: Response): Promise<void> => {
  const { orderId } = req.params;
  const { status } = req.body;
  const userId = req.user?.userId;

  if (!userId) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }
  if (!['Approved', 'Rejected', 'Shipped', 'Delivered'].includes(status)) {
    res.status(400).json({ message: 'Invalid status' });
    return;
  }

  try {
    const order = await Order.findOne({ _id: orderId, sellerId: userId });
    if (!order) {
      res.status(404).json({ message: 'Order not found' });
      return;
    }

    // Validate status transitions
    const validTransitions: Record<string, string[]> = {
      Pending: ['Approved', 'Rejected'],
      Approved: ['Shipped'],
      Shipped: ['Delivered'],
      Rejected: [],
      Delivered: [],
    };

    if (!validTransitions[order.status]?.includes(status)) {
      res.status(400).json({ message: `Cannot transition from ${order.status} to ${status}` });
      return;
    }

    order.status = status;
    await order.save();
    logger.info(`Order ${orderId} updated to ${status} by user ${userId}`);
    res.status(200).json(order);
  } catch (error) {
    logger.error('Update order status error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const getProfile = async (req: AuthRequest, res: Response): Promise<void> => {
  const userId = req.user?.userId;

  if (!userId) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  try {
    const user = await User.findById(userId).select('-password');
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    res.status(200).json(user);
  } catch (error) {
    logger.error('Get profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const updateProfile = async (req: AuthRequest, res: Response): Promise<void> => {
  const { businessName, contactPerson, email, address } = req.body;
  const userId = req.user?.userId;

  if (!userId) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        res.status(400).json({ message: 'Email already in use' });
        return;
      }
    }

    user.businessName = businessName || user.businessName;
    user.contactPerson = contactPerson || user.contactPerson;
    user.email = email || user.email;
    user.address = address || user.address;

    await user.save();
    logger.info(`Profile updated for user ${userId}`);
    res.status(200).json(user);
  } catch (error) {
    logger.error('Update profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const updateDocuments = async (req: AuthRequest, res: Response): Promise<void> => {
  const userId = req.user?.userId;
  const files = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined;

  if (!userId) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  if (!files || typeof files !== 'object') {
    res.status(400).json({ message: 'No files uploaded' });
    return;
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    const uploadDir = path.join(__dirname, '../Uploads');
    await fs.promises.mkdir(uploadDir, { recursive: true });

    const documentPaths: Record<string, string> = { ...user.documents };
    for (const [docType, fileArray] of Object.entries(files)) {
      const file = fileArray[0];
      const fileName = `${userId}_${docType}_${Date.now()}_${file.originalname.replace(/\s/g, '_')}`;
      const filePath = path.join(uploadDir, fileName);
      await fs.promises.writeFile(filePath, file.buffer);
      documentPaths[docType] = fileName;
    }

    user.documents = documentPaths;
    await user.save();
    logger.info(`Documents updated for user ${userId}`);
    res.status(200).json({ message: 'Documents updated successfully' });
  } catch (error) {
    logger.error('Update documents error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const updatePassword = async (req: AuthRequest, res: Response): Promise<void> => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const userId = req.user?.userId;

  if (!userId) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }
  if (newPassword !== confirmPassword) {
    res.status(400).json({ message: 'Passwords do not match' });
    return;
  }

  try {
    const user = await User.findById(userId).select('+password');
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      res.status(400).json({ message: 'Current password is incorrect' });
      return;
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    logger.info(`Password updated for user ${userId}`);
    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    logger.error('Update password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const getMedicines = async (req: AuthRequest, res: Response): Promise<void> => {
  const { search = '', manufacturer = '', category = '', page = '1', limit = '10' } = req.query;
  const userId = req.user?.userId;
  const role = req.user?.role;

  if (!userId || !role) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  try {
    const pageNum = parseInt(page as string);
    const limitNum = parseInt(limit as string);
    const skip = (pageNum - 1) * limitNum;

    const query: any = {
      quantity: { $gt: 0 },
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { batchNumber: { $regex: search, $options: 'i' } },
      ],
    };

    if (manufacturer) query.manufacturerId = manufacturer;
    if (category) query.category = category;

    if (role === 'wholesaler') {
      query.role = 'manufacturer';
    } else if (role === 'distributor') {
      query.role = { $in: ['manufacturer', 'wholesaler'] };
    } else {
      res.status(403).json({ message: 'Invalid role' });
      return;
    }

    const [medicines, total] = await Promise.all([
      Product.find(query)
        .populate('manufacturerId', 'businessName')
        .skip(skip)
        .limit(limitNum)
        .lean(),
      Product.countDocuments(query),
    ]);

    res.status(200).json({
      medicines: medicines.map((m) => ({
        id: m._id,
        name: m.name,
        manufacturer: typeof m.manufacturerId === 'object' && m.manufacturerId !== null && 'businessName' in m.manufacturerId
          ? (m.manufacturerId as any).businessName
          : 'Unknown',
        price: m.price,
        stock: m.quantity,
        minQuantity: m.minQuantity,
        expiry: m.expiryDate.toISOString().split('T')[0],
        category: m.category,
        type: m.category.toLowerCase(),
      })),
      total,
    });
  } catch (error) {
    logger.error('Get medicines error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const createOrder = async (req: AuthRequest, res: Response): Promise<void> => {
  const { shippingInfo, cartItems } = req.body;
  const userId = req.user?.userId;
  const role = req.user?.role;

  if (!userId || !role) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  if (!shippingInfo || !cartItems || !Array.isArray(cartItems) || cartItems.length === 0) {
    res.status(400).json({ message: 'Invalid order data' });
    return;
  }

  try {
    const products = await Product.find({ _id: { $in: cartItems.map((item: any) => item.id) } });
    if (products.length !== cartItems.length) {
      res.status(400).json({ message: 'Some products not found' });
      return;
    }

    const items: any[] = [];
    let totalAmount = 0;
    let totalQuantity = 0;

    for (const cartItem of cartItems) {
      const product = products.find((p: any) => (p._id as mongoose.Types.ObjectId).toString() === cartItem.id);
      if (!product) continue;

      if (cartItem.quantity < product.minQuantity) {
        res.status(400).json({ message: `Minimum order quantity for ${product.name} is ${product.minQuantity}` });
        return;
      }

      if (cartItem.quantity > product.quantity) {
        res.status(400).json({ message: `Insufficient stock for ${product.name}` });
        return;
      }

      items.push({
        productId: product._id,
        name: product.name,
        quantity: cartItem.quantity,
        price: product.price,
      });

      totalAmount += product.price * cartItem.quantity;
      totalQuantity += cartItem.quantity;
    }

    totalAmount = Math.round(totalAmount * 1.18); // Add 18% GST

    const razorpayOrder = await razorpay.orders.create({
      amount: totalAmount * 100, // In paise
      currency: 'INR',
      receipt: `order_${Date.now()}`,
    });

    const order = new Order({
      userId,
      buyerId: userId,
      sellerId: products[0].userId,
      items,
      totalAmount,
      totalQuantity,
      shippingInfo,
      status: 'Pending',
      paymentStatus: 'Pending',
      paymentMethod: 'Razorpay',
      orderId: razorpayOrder.id,
      trackingStatus: ['Ordered'],
    });

    await order.save();

    res.status(201).json({
      order,
      razorpayOrder: {
        id: razorpayOrder.id,
        amount: razorpayOrder.amount,
        currency: razorpayOrder.currency,
        key: process.env.RAZORPAY_KEY_ID,
      },
    });
  } catch (error) {
    logger.error('Create order error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const verifyPayment = async (req: AuthRequest, res: Response): Promise<void> => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, cartItems } = req.body;
  const userId = req.user?.userId;

  if (!userId) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  try {
    const body = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || 'placeholder_secret')
      .update(body.toString())
      .digest('hex');

    if (expectedSignature !== razorpay_signature) {
      res.status(400).json({ message: 'Invalid payment signature' });
      return;
    }

    const order = await Order.findOne({ orderId: razorpay_order_id });
    if (!order) {
      res.status(404).json({ message: 'Order not found' });
      return;
    }

    order.paymentStatus = 'Paid';
    order.transactionId = razorpay_payment_id;
    if (!order.trackingStatus) {
      order.trackingStatus = [];
    }
    order.trackingStatus.push('Payment Confirmed');
    await order.save();

    // Update product quantities
    for (const cartItem of cartItems) {
      await Product.updateOne(
        { _id: cartItem.id },
        { $inc: { quantity: -cartItem.quantity } }
      );
    }

    const buyer = await User.findById(order.buyerId);
    const seller = await User.findById(order.sellerId);
    if (buyer && seller) {
      await sendOrderEmails(order, buyer, seller);
    }

    res.status(200).json({ order, message: 'Payment verified and order confirmed' });
  } catch (error) {
    logger.error('Verify payment error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const getPlacedOrders = async (req: AuthRequest, res: Response): Promise<void> => {
  const { status = '', page = '1', limit = '10' } = req.query;
  const userId = req.user?.userId;

  if (!userId) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  try {
    const pageNum = parseInt(page as string);
    const limitNum = parseInt(limit as string);
    const skip = (pageNum - 1) * limitNum;

    const query: any = { buyerId: userId };
    if (status) query.status = status;

    const [orders, total] = await Promise.all([
      Order.find(query)
        .populate('sellerId', 'businessName')
        .skip(skip)
        .limit(limitNum)
        .lean(),
      Order.countDocuments(query),
    ]);

    res.status(200).json({
      orders: orders.map((o) => ({
        id: o.orderId,
        seller: typeof o.sellerId === 'object' && o.sellerId !== null && 'businessName' in o.sellerId
          ? (o.sellerId as any).businessName
          : 'Unknown',
        items: o.items.map((i: any) => i.name).join(', '),
        date: o.createdAt.toISOString().split('T')[0],
        amount: o.totalAmount,
        status: o.status,
      })),
      total,
    });
  } catch (error) {
    logger.error('Get placed orders error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const trackOrder = async (req: AuthRequest, res: Response): Promise<void> => {
  const { orderId } = req.params;
  const userId = req.user?.userId;

  if (!userId) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  try {
    const order = await Order.findOne({ orderId, buyerId: userId }).lean();
    if (!order) {
      res.status(404).json({ message: 'Order not found' });
      return;
    }

    res.status(200).json({
      orderId: order.orderId,
      status: order.status,
      trackingStatus: order.trackingStatus,
      estimatedDelivery: new Date(order.createdAt.getTime() + 5 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
    });
  } catch (error) {
    logger.error('Track order error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};
