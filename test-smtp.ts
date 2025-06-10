import nodemailer from 'nodemailer';
  import dotenv from 'dotenv';

  dotenv.config();

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    logger: true,
    debug: true,
  });

  async function testSMTP() {
    try {
      console.log('Verifying SMTP connection...');
      await transporter.verify();
      console.log('SMTP connection verified');

      console.log('Sending test email...');
      const info = await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: 'vivekg3216@gmail.com', // Use your email
        subject: 'PharmaChain SMTP Test',
        text: 'This is a test email to verify SMTP configuration.',
      });
      console.log('Test email sent:', info.messageId);
    } catch (error) {
      console.error('SMTP error:', error);
    }
  }

  testSMTP();