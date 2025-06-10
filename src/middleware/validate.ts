import { Request, Response, NextFunction } from 'express';
import { validationResult, check } from 'express-validator';

export const validateRegister = [
  check('name').notEmpty().withMessage('Name is required'),
  check('phone').matches(/^\+?[1-9]\d{9,14}$/).withMessage('Invalid phone number'),
  check('email').isEmail().withMessage('Invalid email address'),
  check('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  check('businessName').notEmpty().withMessage('Business name is required'),
  check('address').notEmpty().withMessage('Address is required'),
];

export const validateOtp = [
  check('idToken').notEmpty().withMessage('ID token is required'),
  check('phone').notEmpty().withMessage('Phone number is required'),
];

export const validateRole = [
  check('id').notEmpty().withMessage('User ID is required'),
  check('role').isIn(['manufacturer', 'wholesaler', 'distributor', 'retailer']).withMessage('Invalid role'),
];

export const validateUserId = [
  check('userId').notEmpty().withMessage('User ID is required'),
];

export const validateRequest = (req: Request, res: Response, next: NextFunction): void => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({ message: errors.array()[0].msg });
    return;
  }
  next();
};
