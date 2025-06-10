import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { logger } from '../config/logger';

// Extend Request interface for user authentication
interface AuthRequest extends Request {
  user?: {
    userId: string;
    role: string;
  };
  admin?: {
    adminId: string;
  };
}

export const authenticateUser = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    res.status(401).json({ message: 'Authentication token required' });
    return;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { userId: string; role: string };
    if (!decoded.userId || !decoded.role) {
      res.status(401).json({ message: 'Invalid token payload' });
      return;
    }
    req.user = { userId: decoded.userId, role: decoded.role };
    next();
  } catch (error) {
    logger.error('User authentication error:', error);
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

export const authenticateAdmin = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    res.status(401).json({ message: 'Authentication token required' });
    return;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { adminId: string };
    if (!decoded.adminId) {
      res.status(401).json({ message: 'Invalid token payload' });
      return;
    }
    req.admin = { adminId: decoded.adminId };
    next();
  } catch (error) {
    logger.error('Admin authentication error:', error);
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

export const restrictToRole = (roles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction): void => {
    if (!req.user || !roles.includes(req.user.role)) {
      res.status(403).json({ message: 'Access denied: Insufficient permissions' });
      return;
    }
    next();
  };
};