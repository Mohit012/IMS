import cors from 'cors';
import express, { Application } from 'express';
import morgan from 'morgan';
import session from 'express-session'; // Added
import passport from './config/passport'; // Added - your passport configuration
import config from './config'; // Added - for session secret
import rootRouter from './routes';
import notFound from './middlewares/notFound';
import globalErrorHandler from './middlewares/globalErrorhandler';

const app: Application = express();

app.use(express.json());
app.use(morgan('dev'));

app.use(cors({ origin: ['http://localhost:5173', 'https://inventory-navy.vercel.app'], credentials: true })); // Added credentials: true for session cookies

// Session middleware - BEFORE passport initialization
app.use(
  session({
    secret: config.jwt_secret || 'fallbackSecret!@#$', // Corrected to lowercase jwt_secret
    resave: false,
    saveUninitialized: false, // Set to true if you want to save sessions that are new but not modified
    cookie: {
      secure: config.nodeEnv === 'production', // Use secure cookies in production
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // e.g., 1 day
    },
  })
);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session()); // For persistent login sessions

// application routes
app.use('/api/v1', rootRouter); // Your existing rootRouter

app.use(globalErrorHandler);

app.use(notFound);

export default app;
