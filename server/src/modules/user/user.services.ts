import httpStatus from 'http-status';
import CustomError from '../../errors/customError';
import generateToken from '../../utils/generateToken';
import { IUser } from './user.interface';
import User from './user.model';
import verifyPassword from '../../utils/verifyPassword';
import bcrypt from 'bcrypt';
import crypto from 'crypto'; // For generating reset token
import config from '../../config'; // Assuming a config file for base URL

// Placeholder for email utility - this needs to be implemented
// Example: import sendEmail from '../../utils/sendEmail';
const sendEmail = async (options: { email: string; subject: string; message: string; html?: string }) => {
  console.log('Email sending to:', options.email);
  console.log('Subject:', options.subject);
  console.log('Message:', options.message);
  // In a real app, integrate with an email service like Nodemailer, SendGrid, etc.
  // For now, this will just log to console.
  return Promise.resolve();
};


class UserServices {
  private model = User;

  // get profile
  async getSelf(userId: string) {
    return this.model.findById(userId);
  }
  // register new user
  async register(payload: IUser) {
    const user = await this.model.create(payload);

    const token = generateToken({ _id: user._id, email: user.email });
    return { token };
  }

  // login existing user
  async login(payload: { email: string; password: string }) {
    const user = await this.model.findOne({ email: payload.email }).select('+password');

    if (user && user.password) { // Ensure user and user.password exist for local login
      await verifyPassword(payload.password, user.password); // payload.password is from login form, so it's expected to be string

      const token = generateToken({ _id: user._id, email: user.email });
      return { token };
    } else if (user && !user.password && user.googleId) { // User exists but has no password (likely OAuth user)
      throw new CustomError(httpStatus.BAD_REQUEST, 'Please login using your Google account.');
    } else {
      throw new CustomError(httpStatus.BAD_REQUEST, 'WrongCredentials');
    }
  }

  // update user profile
  async updateProfile(id: string, payload: Partial<IUser>) {
    return this.model.findByIdAndUpdate(id, payload);
  }

  // change Password
  async changePassword(userId: string, payload: { oldPassword: string; newPassword: string }) {
    const user = await this.model.findById(userId).select('+password');
    if (!user) throw new CustomError(httpStatus.NOT_FOUND, 'User not found');

    // If user has no password (e.g. OAuth user trying to set one via change password)
    // This flow might need to be different, e.g. a "set password" flow.
    // For now, we assume changePassword is for users who already have a password.
    if (!user.password) {
      throw new CustomError(httpStatus.BAD_REQUEST, 'Password not set for this account. Cannot change password.');
    }

    const matchedPassword = await bcrypt.compare(payload.oldPassword, user.password);

    if (!matchedPassword) {
      throw new CustomError(httpStatus.BAD_REQUEST, 'Old Password does not match!');
    }

    // New password will be hashed by the pre-save hook in user.model.ts
    user.password = payload.newPassword;
    const updatedUser = await user.save();

    return updatedUser;
  }

  // forgot password
  async forgotPassword(email: string) {
    const user = await this.model.findOne({ email });
    if (!user) {
      // To prevent email enumeration, don't reveal if the user was found or not.
      // Simply return, and the controller will send a generic success message.
      console.warn(`Password reset attempt for non-existent email: ${email}`);
      return;
    }

    // Generate the reset token
    const resetToken = crypto.randomBytes(32).toString('hex');

    // Hash token and set to database (store hashed version for security)
    user.passwordResetToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');

    user.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000); // Token expires in 10 minutes

    await user.save({ validateBeforeSave: false }); // Save without validating other fields

    // Create reset URL (adjust client URL as needed)
    const resetURL = `${config.CLIENT_URL || 'http://localhost:5173'}/reset-password/${resetToken}`;

    const message = `You are receiving this email because you (or someone else) has requested the reset of a password. Please make a PUT request to: \n\n ${resetURL} \n\nIf you did not request this, please ignore this email and your password will remain unchanged.\n This link will expire in 10 minutes.`;

    try {
      await sendEmail({
        email: user.email,
        subject: 'Your Password Reset Token (valid for 10 min)',
        message,
        // html: `<p>...</p>` // Optionally, send an HTML email
      });
      // Controller will send success response
    } catch (err) {
      console.error('Error sending password reset email:', err);
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });
      throw new CustomError(httpStatus.INTERNAL_SERVER_ERROR, 'There was an error sending the email. Try again later.');
    }
  }

  // reset password
  async resetPassword(token: string, newPasswordString: string) {
    // Get user based on the hashed token and ensure it's not expired
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const user = await this.model.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      throw new CustomError(httpStatus.BAD_REQUEST, 'Token is invalid or has expired');
    }

    // Set the new password (it will be hashed by the pre-save hook)
    user.password = newPasswordString;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save(); // This will trigger the pre-save hook to hash the password

    // Optionally, log the user in by generating a new JWT token here
    // const jwtToken = generateToken({ _id: user._id, email: user.email });
    // return { token: jwtToken };
    // For now, just confirm success, user can login manually.
  }
}

const userServices = new UserServices();
export default userServices;
