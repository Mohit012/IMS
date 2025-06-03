import passport from 'passport';
import { Strategy as GoogleStrategy, Profile, VerifyCallback } from 'passport-google-oauth20';
import User from '../modules/user/user.model';
import { IUser } from '../modules/user/user.interface'; // Re-added this import
import config from './index';
import generateToken from '../utils/generateToken';
import { PassportUserType } from '../types/express';

// Log configuration values when this module is loaded
console.log('--- PASSPORT MODULE LOAD ---');
console.log('GOOGLE_CLIENT_ID (from config):', config.GOOGLE_CLIENT_ID);
console.log('GOOGLE_CLIENT_SECRET (from config):', config.GOOGLE_CLIENT_SECRET ? 'Loaded' : 'NOT LOADED or Empty');
console.log('SERVER_URL (from config):', config.SERVER_URL);
console.log('Configured PORT (from config):', config.port);
const constructedCallbackURL = `${config.SERVER_URL || `http://localhost:${config.port || 8000}`}/api/users/auth/google/callback`;
console.log('Constructed Callback URL for Strategy:', constructedCallbackURL);
console.log('--- END PASSPORT MODULE LOAD ---');
passport.use(
  new GoogleStrategy(
    {
      clientID: config.GOOGLE_CLIENT_ID!, // Ensure this is in your .env and config
      clientSecret: config.GOOGLE_CLIENT_SECRET!, // Ensure this is in your .env and config
      callbackURL: `${config.SERVER_URL || `http://localhost:${config.port || 8000}`}/api/users/auth/google/callback`,
      scope: ['profile', 'email'],
    },
    async (accessToken: string, refreshToken: string, profile: Profile, done: VerifyCallback) => {
      try {
        let user: PassportUserType | null = await User.findOne({ googleId: profile.id });

        if (user) {
          return done(null, user);
        }

        if (profile.emails && profile.emails.length > 0) {
          const googleEmail = profile.emails[0].value;
          user = await User.findOne({ email: googleEmail });

          if (user) {
            user.googleId = profile.id;
            if (!user.avatar && profile.photos && profile.photos.length > 0) {
              user.avatar = profile.photos[0].value;
            }
            await user.save();
            return done(null, user);
          }
        }

        const newUserFields: Partial<IUser> = {
          googleId: profile.id,
          email: profile.emails && profile.emails.length > 0 ? profile.emails[0].value : undefined,
          name: profile.displayName,
          avatar: profile.photos && profile.photos.length > 0 ? profile.photos[0].value : undefined,
          role: 'USER',
          status: 'ACTIVE',
        };
        
        if (!newUserFields.email) {
          return done(new Error('Email not provided by Google. Cannot create account.'));
        }
        
        // If your schema requires a password even for OAuth users, you might need to:
        // 1. Generate a random, unusable password:
        // newUserFields.password = crypto.randomBytes(16).toString('hex');
        // 2. Or, adjust your schema to make password optional if googleId is present.
        // For now, assuming the schema allows password to be absent if googleId is present,
        // or the pre-save hook for password hashing handles undefined passwords gracefully (e.g., by not hashing).
        // The current user.model.ts has password as required:true, select:0. This will cause an error on save
        // if password is not provided. We should make password optional in the schema or provide one.
        // Let's make it optional for now in the IUser interface and schema for OAuth users.
        // This change should be done in user.interface.ts and user.model.ts

        const newUser = new User(newUserFields);
        await newUser.save();
        return done(null, newUser as PassportUserType);
      } catch (error) {
        if (error instanceof Error) {
          return done(error, undefined);
        }
        return done(new Error('An unknown error occurred during Google OAuth.'), undefined);
      }
    }
  )
);

// Use PassportUserType explicitly here
passport.serializeUser((user: PassportUserType, done) => {
  const token = generateToken({ _id: user._id, email: user.email!, role: user.role });
  done(null, { id: user.id, token });
});

passport.deserializeUser(async (serializedData: { id: string; token: string }, done) => {
  try {
    const userFromDb = await User.findById(serializedData.id);
    if (userFromDb) {
      // Ensure the deserialized user conforms to PassportUserType
      const deserializedUser: PassportUserType = userFromDb.toObject() as PassportUserType;
      deserializedUser.token = serializedData.token; // Attach the token
      return done(null, deserializedUser);
    }
    return done(null, false);
  } catch (error) {
    if (error instanceof Error) {
      return done(error, false);
    }
    return done(new Error('Failed to deserialize user'), false);
  }
});

export default passport;