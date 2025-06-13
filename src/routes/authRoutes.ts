import { Router } from 'express';
import {
  register,
  login,
  chooseRole,
  uploadDocs,
  verifyUser,
  sendConfirmationEmail,
  sendEmailOTP,
  verifyEmailOTP,
  requestPasswordReset,
  resetPassword,
} from '../controllers/authController';
import {
  validateRegister,
  validateRole,
  validateUserId,
  validateRequest,
} from '../middleware/validate';
import multer from 'multer';
import rateLimit from 'express-rate-limit';

const router = Router();
const storage = multer.memoryStorage(); // instead of diskStorage
const upload = multer({ storage });

const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 3, // 3 requests per email
  message: 'Too many OTP requests. Please try again later.',
  keyGenerator: (req) => req.body.email || req.ip,
});

router.post('/register', validateRegister, validateRequest, register);
router.post('/login', login);
router.post('/send-email-otp', otpLimiter, sendEmailOTP);
router.post('/verify-email-otp', verifyEmailOTP);
router.post('/request-password-reset', otpLimiter, requestPasswordReset);
router.post('/reset-password', resetPassword);
router.post('/choose-role', validateRole, validateRequest, chooseRole);
router.post(
  '/upload-docs',
  upload.fields([
    { name: 'aadhaar', maxCount: 1 },
    { name: 'pan', maxCount: 1 },
    { name: 'gst', maxCount: 1 },
    { name: 'drugLicense', maxCount: 1 },
  ]),
  validateUserId,
  validateRequest,
  uploadDocs
);
router.post('/verify-user', validateUserId, validateRequest, verifyUser);
router.post('/send-confirmation-email', validateUserId, validateRequest, sendConfirmationEmail);

export default router;