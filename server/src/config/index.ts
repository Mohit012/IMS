import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.join(process.cwd(), '.env') }); // Corrected path join

export default {
  nodeEnv: process.env.NODE_ENV,
  port: process.env.PORT,
  database_url: process.env.DATABASE_URL,
  jwt_secret: process.env.JWT_SECRET,
  CLIENT_URL: process.env.CLIENT_URL,
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID, // Added
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET, // Added
  SERVER_URL: process.env.SERVER_URL, // Added (e.g., http://localhost:8000 or your production URL)
};
