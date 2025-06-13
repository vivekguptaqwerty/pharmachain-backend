import { Router } from 'express';
import { v2 as cloudinary } from 'cloudinary';
import streamifier from 'streamifier';

const router = Router();

router.get('/test-cloudinary', async (req, res) => {
  const dummyImageBuffer = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAUA' +
    'AAAFCAYAAACNbyblAAAAHElEQVQI12P4' +
    '//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==',
    'base64'
  );

  try {
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        { folder: 'test' },
        (error, result) => {
          if (error) {
            console.error('❌ Upload failed:', error);
            reject(error);
          } else {
            if (result && result.secure_url) {
              console.log('✅ Upload success:', result.secure_url);
            } else {
              console.log('✅ Upload success, but secure_url is missing:', result);
            }
            resolve(result);
          }
        }
      );

      streamifier.createReadStream(dummyImageBuffer).pipe(uploadStream);
    });

    res.status(200).json({ success: true, result });
  } catch (error) {
    res.status(500).json({ success: false, error });
  }
});

export default router;
