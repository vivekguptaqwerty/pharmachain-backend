import bcrypt from 'bcryptjs';
import { Admin } from './models/Admin';
import { connectDB } from './config/database';
import dotenv from 'dotenv';

dotenv.config();

const createAdmin = async () => {
  await connectDB();
  const email = 'admin@example.com';
  const password = 'secureAdminPassword123';
  const hashedPassword = await bcrypt.hash(password, 10);

  const admin = new Admin({
    email,
    password: hashedPassword,
  });

  await admin.save();
  console.log(`Admin created: ${email}`);
  process.exit(0);
};

createAdmin().catch(console.error);