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
  getManufacturers,
} from '../controllers/userController';
import { authenticateUser, restrictToRole } from '../middleware/auth';
import multer from 'multer';

const router = express.Router();

// Configure multer to store files in memory
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|pdf/;
    const extname = filetypes.test(file.originalname.toLowerCase().split('.').pop() || '');
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
router.get('/manufacturers', getManufacturers);
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