import express from 'express';
import cors from 'cors';
import authRoutes from './routes/auth.routes';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware: Security headers
app.use(helmet());

// Middleware: Content Security Policy (CSP)
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", 'http://localhost:5173'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      fontSrc: ["'self'"],
      formAction: ["'self'"],
      scriptSrcAttr: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);

// Middleware: CORS
app.use(
  cors({
    origin: 'http://localhost:5173',
    credentials: true,
  })
);

// Middleware: Body parsing and cookies
app.use(express.json());
app.use(cookieParser());

// Middleware: Serve static files
app.use(express.static('static'));

// Middleware: Rate limiting (global)
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests, please try again later.',
});
app.use(globalLimiter);

// Routes
app.use('/auth', authRoutes);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export default app;