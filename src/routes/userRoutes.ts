import express from 'express';
import {
  getDashboard,
  addProduct,
  getProducts,
  updateProduct,
  deleteProduct,
  getOrders,
  updateOrderStatus,
  getProfile,
  updateProfile,
  updateDocuments,
  updatePassword,
  getMedicines,
  createOrder,
  verifyPayment,
  getPlacedOrders,
  trackOrder,
} from '../controllers/userController';
import { authenticateUser, restrictToRole } from '../middleware/auth';
import multer from 'multer';
import path from 'path';

const router = express.Router();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'src/Uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|pdf/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDFs are allowed'));
    }
  },
});


router.use(authenticateUser);
router.use(restrictToRole(['manufacturer', 'wholesaler', 'distributor']));

router.post('/products', upload.single('image'), addProduct);
router.get('/products', getProducts);
router.put('/products/:id', upload.single('image'), updateProduct);
router.delete('/products/:id', deleteProduct);
router.get('/dashboard', getDashboard);
router.get('/orders', getOrders);
router.put('/orders/:orderId', updateOrderStatus);
router.get('/profile', getProfile);
router.put('/profile', updateProfile);
router.post(
  '/documents',
  upload.fields([
    { name: 'gstCertificate', maxCount: 1 },
    { name: 'drugLicense', maxCount: 1 },
  ]),
  updateDocuments
);
router.put('/password', updatePassword);
router.get('/medicines', getMedicines);
router.post('/orders', createOrder);
router.post('/orders/verify', verifyPayment);
router.get('/orders/placed', getPlacedOrders);
router.get('/orders/:orderId/track', trackOrder);

export default router;