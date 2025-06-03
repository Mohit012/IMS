import httpStatus from 'http-status';
import asyncHandler from '../../lib/asyncHandler';
import sendResponse from '../../lib/sendResponse';
import userServices from './user.services';
import CustomError from '../../errors/customError'; // Added import

class UserControllers {
  private services = userServices;

  // get self profile
  getSelf = asyncHandler(async (req, res) => {
    if (!req.user) {
      throw new CustomError(httpStatus.UNAUTHORIZED, 'You are not authorized');
    }
    const result = await this.services.getSelf(req.user._id.toString());

    sendResponse(res, {
      success: true,
      statusCode: httpStatus.CREATED,
      message: 'User profile retrieved successfully!',
      data: result
    });
  });

  // register new account
  register = asyncHandler(async (req, res) => {
    const result = await this.services.register(req.body);

    sendResponse(res, {
      success: true,
      statusCode: httpStatus.CREATED,
      message: 'User registered successfully!',
      data: result
    });
  });

  // login into your registered account
  login = asyncHandler(async (req, res) => {
    const result = await this.services.login(req.body);

    sendResponse(res, {
      success: true,
      statusCode: httpStatus.OK,
      message: 'User login successfully!',
      data: result
    });
  });

  // update profile
  updateProfile = asyncHandler(async (req, res) => {
    if (!req.user) {
      throw new CustomError(httpStatus.UNAUTHORIZED, 'You are not authorized');
    }
    const result = await this.services.updateProfile(req.user._id.toString(), req.body);

    sendResponse(res, {
      success: true,
      statusCode: httpStatus.OK,
      message: 'User Profile updated successfully!',
      data: result
    });
  });

  // change Password
  changePassword = asyncHandler(async (req, res) => {
    if (!req.user) {
      throw new CustomError(httpStatus.UNAUTHORIZED, 'You are not authorized');
    }
    const result = await this.services.changePassword(req.user._id.toString(), req.body);

    sendResponse(res, {
      success: true,
      statusCode: httpStatus.OK,
      message: 'Password changed successfully!',
      data: result
    });
  });

  // forgot password
  forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;
    await this.services.forgotPassword(email); // Service to be implemented

    sendResponse(res, {
      success: true,
      statusCode: httpStatus.OK,
      message: 'Password reset link sent successfully! Please check your email.',
      // No data is typically sent back here for security reasons
    });
  });

  // reset password
  resetPassword = asyncHandler(async (req, res) => {
    const { token, newPassword } = req.body;
    await this.services.resetPassword(token, newPassword); // Service to be implemented

    sendResponse(res, {
      success: true,
      statusCode: httpStatus.OK,
      message: 'Password has been reset successfully!',
      // No data is typically sent back here
    });
  });
}

const userControllers = new UserControllers();
export default userControllers;
