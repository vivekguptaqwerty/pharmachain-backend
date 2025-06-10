import nodemailer from 'nodemailer';
import { logger } from './logger';

export const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: "vivekg3216@gmail.com" ,
    pass: "rtnzfotcabilzwlm",
  },
});

transporter.verify((error) => {
  if (error) {
    logger.error('Nodemailer configuration error:', error);
  } else {
    logger.info('Nodemailer configured successfully');
  }
});