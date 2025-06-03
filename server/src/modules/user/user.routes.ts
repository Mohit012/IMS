import { Router } from 'express';
import passport from '../../config/passport'; // Import configured passport
import userControllers from './user.controllers';
import validateRequest from '../../middlewares/validateRequest';
import userValidator from './user.validator';
import verifyAuth from '../../middlewares/verifyAuth';
import config from '../../config'; // For client URL redirect

const userRoutes = Router();

// Local Auth
userRoutes.post('/register', validateRequest(userValidator.registerSchema), userControllers.register);
userRoutes.post('/login', validateRequest(userValidator.loginSchema), userControllers.login);

// Password Recovery Routes
userRoutes.post(
  '/forgot-password',
  validateRequest(userValidator.forgotPasswordSchema), // Schema to be created
  userControllers.forgotPassword // Controller to be created
);
userRoutes.post(
  '/reset-password',
  validateRequest(userValidator.resetPasswordSchema), // Schema to be created
  userControllers.resetPassword
);

// Google OAuth Routes
userRoutes.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

userRoutes.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    // successRedirect: config.CLIENT_URL || 'http://localhost:5173', // Redirect to client on success
    failureRedirect: `${config.CLIENT_URL || 'http://localhost:5173'}/login?oauthError=true`, // Redirect to client login on failure
    session: true, // Ensure session is true if you're using it
  }),
  (req, res) => {
    // Successful authentication, req.user should be populated by Passport.
    // req.user will have the structure { id: '...', token: '...' } from serializeUser
    // We need to send this token to the client.
    // One way is to redirect with the token in a query parameter.
    // Or, if the client can make a subsequent request to fetch user data,
    // the session will handle it. For SPA, redirecting with token is common.

    // req.user is now typed as Express.User, which is PassportUserType
    if (req.user && req.user.token) {
      const token = req.user.token;
      // Redirect to a client-side route that can handle the token
      // For example, a route that saves the token and then redirects to the dashboard.
      res.redirect(`${config.CLIENT_URL || 'http://localhost:5173'}/oauth-callback?token=${token}`);
    } else {
      // This case implies that serializeUser might not have attached the token,
      // or req.user is not populated as expected.
      console.error('OAuth callback: req.user or req.user.token is missing after authentication.');
      res.redirect(`${config.CLIENT_URL || 'http://localhost:5173'}/login?oauthError=true&message=AuthenticationFailed`);
    }
  }
);


userRoutes.get('/self', verifyAuth, userControllers.getSelf);
userRoutes.post(
  '/change-password',
  verifyAuth,
  validateRequest(userValidator.changePasswordSchema),
  userControllers.changePassword
);
userRoutes.patch('/', verifyAuth, userControllers.updateProfile);

export default userRoutes;
