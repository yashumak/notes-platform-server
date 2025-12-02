import express from 'express';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import authRoutes from './routes/auth.routes.js';
import notesRoutes from './routes/notes.routes.js';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

import connectDB from './config/db.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Connect to MongoDB
connectDB();

// Middleware
app.use(cookieParser());
app.use(express.json()); // For parsing application/json
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(helmet());

// CSRF protection



// Rate limiting to prevent brute-force attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per 15 minutes per IP
  message: 'Too many requests from this IP, please try again after 15 minutes',
});
app.use(limiter);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/notes', notesRoutes);

// CSRF token endpoint


// Basic error handling middleware
app.use((err, req, res, next) => {
  console.error('Backend Error:', err.message);
  console.error('Error Stack:', err.stack);
  console.error('Request Body:', req.body);
  console.error('Request Headers:', req.headers);

  let statusCode = 500;
  let message = 'Something went wrong!';

  if (err.code === 'EBADCSRFTOKEN') {
    statusCode = 403;
    message = 'Invalid CSRF token';
  } else if (err.name === 'CastError') {
    statusCode = 400;
    message = 'Invalid ID';
  } else if (err.name === 'ValidationError') { // Mongoose validation errors
    statusCode = 400;
    message = err.message;
  } else if (err.array) { // express-validator errors
    statusCode = 400;
    message = err.array().map(error => error.msg).join(', ');
  }

  res.status(statusCode).json({ message });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
