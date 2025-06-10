import { Request, Response } from 'express';
import { User } from '../models/User';
import { OTP } from '../models/OTP';
import { logger } from '../config/logger';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { promises as fs } from 'fs';
import path from 'path';
import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'vivekg3216@gmail.com',
    pass: 'rtnzfotcabilzwlm',
  },
  logger: true,
  debug: true,
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 10000,
});

transporter.verify((error, success) => {
  if (error) {
    logger.error('SMTP configuration error:', error);
  } else {
    logger.info('SMTP server ready');
  }
});

export const register = async (req: Request, res: Response): Promise<void> => {
  const { name, phone, email, password, businessName, address, otp } = req.body;

  if (!name || !name.trim()) {
    res.status(400).json({ message: 'Name is required' });
    return;
  }
  if (!phone || !phone.trim()) {
    res.status(400).json({ message: 'Phone number is required' });
    return;
  }
  if (!email || !email.trim()) {
    res.status(400).json({ message: 'Email is required' });
    return;
  }
  if (!password || !password.trim()) {
    res.status(400).json({ message: 'Password is required' });
    return;
  }
  if (!businessName || !businessName.trim()) {
    res.status(400).json({ message: 'Business name is required' });
    return;
  }
  if (!address || !address.trim()) {
    res.status(400).json({ message: 'Address is required' });
    return;
  }
  if (!otp || !otp.trim()) {
    res.status(400).json({ message: 'OTP is required' });
    return;
  }

  try {
    const otpRecord = await OTP.findOne({
      email,
      type: 'signup',
      verified: false,
      expiresAt: { $gt: new Date() },
    }).sort({ createdAt: -1 });

    if (!otpRecord || !(await bcrypt.compare(otp, otpRecord.otp))) {
      res.status(400).json({ message: 'Invalid or expired OTP' });
      return;
    }

    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      res.status(400).json({ message: 'User with this email or phone already exists' });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, phone, email, password: hashedPassword, businessName, address, role: null });
    await user.save();

    otpRecord.verified = true;
    await otpRecord.save();

    logger.info(`User registered: ${email}`);
    res.status(201).json({ userId: user._id });
  } catch (error) {
    logger.error('Register error:', error);
    res.status(500).json({ message: 'Registration failed' });
  }
};

export const chooseRole = async (req: Request, res: Response): Promise<void> => {
  const { id, role } = req.body;

  if (!id || !role) {
    res.status(400).json({ message: 'User ID and role are required' });
    return;
  }

  if (!['manufacturer', 'wholesaler', 'distributor', 'retailer', 'admin'].includes(role)) {
    res.status(400).json({ message: 'Invalid role' });
    return;
  }

  try {
    const user = await User.findById(id);
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    user.role = role;
    await user.save();

    logger.info(`Role selected for user ${id}: ${role}`);
    res.status(200).json({ message: 'Role selected successfully' });
  } catch (error) {
    logger.error('Role selection failed:', error);
    res.status(500).json({ message: 'Role selection failed' });
  }
};

export const login = async (req: Request, res: Response): Promise<void> => {
  const { phone, password } = req.body;

  try {
    const user = await User.findOne({ phone }).select('+password');
    if (!user) {
      logger.info(`Login failed: No user found with phone ${phone}`);
      res.status(401).json({ message: 'Invalid phone number or password' });
      return;
    }

    logger.info(`User found: ${user.email}, status: ${user.status}`);
    if (user.status !== 'approved') {
      res.status(403).json({ message: 'Account not approved. Please contact support.' });
      return;
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      logger.info(`Login failed: Password mismatch for phone ${phone}`);
      res.status(401).json({ message: 'Invalid phone number or password' });
      return;
    }

    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET as string,
      { expiresIn: '1h' }
    );

    logger.info(`User logged in: ${phone}`);
    res.status(200).json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role,
      },
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
};

export const sendEmailOTP = async (req: Request, res: Response): Promise<void> => {
  const { email, type } = req.body;

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    res.status(400).json({ message: 'Valid email is required' });
    return;
  }

  if (!['signup', 'password_reset'].includes(type)) {
    res.status(400).json({ message: 'Invalid OTP type' });
    return;
  }

  try {
    const recentOTPs = await OTP.countDocuments({
      email,
      type,
      createdAt: { $gte: new Date(Date.now() - 5 * 60 * 1000) },
    });
    if (recentOTPs >= 3) {
      res.status(429).json({ message: 'Too many OTP requests. Try again later.' });
      return;
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOTP = await bcrypt.hash(otp, 10);

    await OTP.create({
      email,
      otp: hashedOTP,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      verified: false,
      type,
    });

    const mailOptions = {
      from: process.env.SMTP_USER,
      to: email,
      subject: `PharmaChain ${type === 'signup' ? 'Email Verification' : 'Password Reset'} OTP`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <h2 style="color: #0066cc; text-align: center;">PharmaChain</h2>
          <p style="font-size: 16px;">Dear User,</p>
          <p style="font-size: 16px;">Please use the following One-Time Password (OTP) to ${
            type === 'signup' ? 'verify your email' : 'reset your password'
          }:</p>
          <h3 style="font-size: 24px; color: #0066cc; text-align: center; background: #f0f0f0; padding: 10px; border-radius: 4px;">${otp}</h3>
          <p style="font-size: 14px; color: #666;">This OTP is valid for 10 minutes. Do not share it with anyone.</p>
          <p style="font-size: 14px;">If you didn't request this, please ignore this email.</p>
          <p style="font-size: 14px; text-align: center; color: #666;">© 2025 PharmaChain. All rights reserved.</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
    logger.info(`OTP sent to ${email} for ${type}`);
    res.status(200).json({ message: 'OTP sent to your email' });
  } catch (error) {
    logger.error('Send OTP error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const verifyEmailOTP = async (req: Request, res: Response): Promise<void> => {
  const { email, otp, type } = req.body;

  if (!email || !otp || !['signup', 'password_reset'].includes(type)) {
    res.status(400).json({ message: 'Email, OTP, and valid type are required' });
    return;
  }

  try {
    const otpRecord = await OTP.findOne({
      email,
      type,
      expiresAt: { $gt: new Date() },
      verified: false,
    }).sort({ createdAt: -1 });

    if (!otpRecord) {
      res.status(400).json({ message: 'Invalid or expired OTP' });
      return;
    }

    const isMatch = await bcrypt.compare(otp, otpRecord.otp);
    if (!isMatch) {
      res.status(400).json({ message: 'Invalid OTP' });
      return;
    }

    otpRecord.verified = true;
    await otpRecord.save();

    res.status(200).json({ message: 'OTP verified successfully' });
  } catch (error) {
    logger.error('Verify OTP error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const requestPasswordReset = async (req: Request, res: Response): Promise<void> => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      res.status(404).json({ message: 'Email not found' });
      return;
    }

    await sendEmailOTP({ body: { email, type: 'password_reset' } } as Request, res);
  } catch (error) {
    logger.error('Password reset request error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const resetPassword = async (req: Request, res: Response): Promise<void> => {
  const { email, newPassword } = req.body;

  try {
    const otpRecord = await OTP.findOne({
      email,
      type: 'password_reset',
      expiresAt: { $gt: new Date() },
      verified: true,
    }).sort({ createdAt: -1 });

    if (!otpRecord) {
      res.status(400).json({ message: 'OTP not verified or expired' });
      return;
    }

    const user = await User.findOne({ email });
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    logger.info(`New password hash for ${email}: ${hashedPassword}`);
    user.password = hashedPassword;
    const saveResult = await user.save();
    logger.info(`Save result for user ${email}: ${JSON.stringify(saveResult)}`);

    const updatedUser = await User.findOne({ email }).select('+password');
    logger.info(`Stored password hash after save for ${email}: ${updatedUser?.password}`);

    await OTP.deleteOne({ _id: otpRecord._id });

    logger.info(`Password reset for user: ${email}`);
    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    logger.error('Password reset error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

export const uploadDocs = async (req: Request, res: Response): Promise<void> => {
  const { userId } = req.body;
  const files = req.files as { [fieldname: string]: Express.Multer.File[] };

  try {
    if (!userId) {
      res.status(400).json({ message: 'User ID is required' });
      return;
    }

    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    const uploadDir = path.join(__dirname, '../../Uploads');
    await fs.mkdir(uploadDir, { recursive: true });

    const documentPaths: Record<string, string> = {};
    for (const [docType, fileArray] of Object.entries(files)) {
      const file = fileArray[0];
      const fileName = `${userId}_${docType}_${file.originalname.replace(/\s/g, '_')}`;
      const filePath = path.join(uploadDir, fileName);
      await fs.writeFile(filePath, file.buffer);
      documentPaths[docType] = fileName;
    }

    user.documents = documentPaths;
    await user.save();
    logger.info(`Documents uploaded for user ${userId}`);
    res.status(200).json({ message: 'Documents uploaded successfully' });
  } catch (error) {
    logger.error('Document upload error:', error);
    res.status(500).json({ message: 'Document upload failed' });
  }
};

export const verifyUser = async (req: Request, res: Response): Promise<void> => {
  const { userId } = req.body;

  try {
    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    user.status = 'approved';
    await user.save();

    logger.info(`User verified: ${userId}`);
    res.status(200).json({ message: 'User verified successfully' });
  } catch (error) {
    logger.error('User verification failed:', error);
    res.status(500).json({ message: 'User verification failed' });
  }
};

export const sendConfirmationEmail = async (req: Request, res: Response): Promise<void> => {
  const { userId } = req.body;

  try {
    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to: user.email,
      subject: 'PharmaChain Account Approved',
      html: `
        <h2>Welcome to PharmaChain!</h2>
        <p>Your account has been approved. You can now log in and start using the platform.</p>
        <p><a href="http://localhost:3000/login">Log in to PharmaChain</a></p>
      `,
    });

    logger.info(`Confirmation email sent to: ${user.email}`);
    res.status(200).json({ message: 'Confirmation email sent' });
  } catch (error) {
    logger.error('Failed to send confirmation email:', error);
    res.status(500).json({ message: 'Failed to send confirmation email' });
  }
};