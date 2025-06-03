import { z } from 'zod';

const registerSchema = z.object({
  name: z.string(),
  email: z.string().email(),
  password: z.string().min(6, { message: 'password must have 6 characters' })
});

const updatedProfileSchema = z.object({
  name: z.string().optional(),
  title: z.string().optional(),
  description: z.string().optional(),
  avatar: z.string().optional()
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6, { message: 'password must have 6 characters' })
});

const changePasswordSchema = z.object({
  oldPassword: z
    .string({ required_error: 'Old Password is required!' })
    .min(6, { message: 'old password must have 6 characters' }),
  newPassword: z
    .string({ required_error: 'New Password is required!' })
    .min(6, { message: 'new password must have 6 characters' })
});

const forgotPasswordSchema = z.object({
  email: z.string().email({ message: 'Invalid email address' }),
});

const resetPasswordSchema = z.object({
  token: z.string({ required_error: 'Reset token is required' }),
  newPassword: z.string().min(8, { message: 'Password must be at least 8 characters long' })
  // Consider adding more complex password rules here if needed, e.g., regex for uppercase, number, symbol
  // .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, {
  //   message: "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character."
  // })
});

const userValidator = {
  registerSchema,
  loginSchema,
  updatedProfileSchema,
  changePasswordSchema,
  forgotPasswordSchema, // Added
  resetPasswordSchema,  // Added
};
export default userValidator;
