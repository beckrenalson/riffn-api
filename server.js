import dotenv from 'dotenv';
dotenv.config();

console.log('Server starting...');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('JWT_SECRET loaded:', !!process.env.JWT_SECRET); // Only log if it exists, not the value itself for security
console.log('JWT_REFRESH_SECRET loaded:', !!process.env.JWT_REFRESH_SECRET); // Only log if it exists

import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import path from 'path';
import trackRoutes from "./routes/tracks.js"
import authRoutes from './routes/auth.js';
import subgenreRoutes from './routes/subgenres.js';
import instrumentRoutes from './routes/instruments.js';
import userRoutes from './routes/users.js';
import uploadRoutes from './routes/uploads.js';
import connectionRoutes from './routes/connections.js';
import { protect } from './middleware/authMiddleware.js';
import { fileURLToPath } from 'url';

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const allowedOrigins = [
  'http://localhost:5173',                    // dev
  'https://riffn.vercel.app'     // prod
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use("/api/auth", authRoutes);
app.use("/api/tracks", trackRoutes);
app.use('/api/subgenres', subgenreRoutes);
app.use('/api/instruments', instrumentRoutes);
app.use('/api/users', protect, userRoutes);
app.use('/api/uploads', uploadRoutes);
app.use('/api/connections', protect, connectionRoutes);


const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
