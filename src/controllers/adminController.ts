import { Request, Response } from 'express';
import { User } from '../models/User';
import { Admin } from '../models/Admin';
import { logger } from '../config/logger';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { transporter } from '../config/nodemailer';

// Extend Request interface to include user property
interface AuthRequest extends Request {
  user?: { adminId: string };
}

export const adminLogin = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;

  try {
    const admin = await Admin.findOne({ email });
    if (!admin) {
      res.status(401).json({ message: 'Invalid credentials' });
      return;
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ adminId: admin._id }, process.env.JWT_SECRET as string, {
      expiresIn: '1h',
    });

    logger.info(`Admin logged in: ${email}`);
    res.status(200).json({ token });
  } catch (error) {
    logger.error('Admin login error:', error);
    throw new Error('Admin login failed');
  }
};

export const getUsers = async (req: AuthRequest, res: Response) => {
  try {
    const users = await User.find().select('-password');
    logger.info(`Fetched user list for admin ${req.user?.adminId}`);
    res.status(200).json(users);
  } catch (error) {
    logger.error('Get users error:', error);
    throw new Error('Failed to fetch users');
  }
};

export const verifyUser = async (req: AuthRequest, res: Response): Promise<void> => {
  const { userId, status } = req.body;

  try {
    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({ message: 'User not found' });
        return;
    }

    if (!['approved', 'rejected'].includes(status)) {
      res.status(400).json({ message: 'Invalid status' });
    }

    user.status = status;
    await user.save();

    if (status === 'approved') {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'PharmaChain Account Approved',
        html: `
          <h2>Welcome to PharmaChain!</h2>
          <p>Your account has been approved. You can now log in and start using the platform.</p>
          <p><a href="http://localhost:3000/login">Log in to PharmaChain</a></p>
        `,
      });
      logger.info(`Confirmation email sent to: ${user.email}`);
    }

    logger.info(`User ${userId} status updated to: ${status} by admin ${req.user?.adminId}`);
    res.status(200).json({ message: `User ${status} successfully` });
  } catch (error) {
    logger.error('User verification error:', error);
    throw new Error('User verification failed');
  }
};