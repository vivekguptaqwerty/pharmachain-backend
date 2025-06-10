import { User } from './models/User';
import { connectDB } from './config/database';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config();

const fixDocumentPaths = async () => {
  await connectDB();
  const users = await User.find();

  for (const user of users) {
    const updatedDocuments = new Map<string, string>();

    for (const [docType, filePath] of Object.entries(user.documents || {})) {
      // Skip internal Mongoose keys
      if (docType.startsWith("__$") || docType.startsWith("$")) {
        continue;
      }

      if (typeof filePath === 'string') {
        const fileName = path.basename(filePath);
        updatedDocuments.set(docType, fileName);
      } else {
        console.warn(`Skipping invalid document path for user ${user._id}, docType: ${docType}`, filePath);
      }
    }

    if (updatedDocuments.size > 0) {
      user.documents = updatedDocuments as any; // Cast to `any` to avoid Mongoose Map issues
      await user.save();
      console.log(`✅ Updated documents for user ${user._id}`);
    }
  }

  console.log('🎉 Document path migration complete');
  process.exit(0);
};

fixDocumentPaths().catch(console.error);
