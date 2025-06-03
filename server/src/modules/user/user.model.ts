import { Schema, model } from 'mongoose';
import { IUser } from './user.interface';
import hashPassword from '../../utils/hashPassword';
import { UserRole, UserStatus } from '../../constant/userRole';

const userSchema = new Schema<IUser>(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, select: 0 }, // No longer strictly required at schema level
    title: { type: String },
    description: { type: String },
    avatar: { type: String },
    role: { type: String, enum: UserRole, default: 'USER' },
    status: { type: String, enum: UserStatus, default: 'ACTIVE' },
    address: { type: String },
    phone: { type: String },
    city: { type: String },
    country: { type: String },
    facebook: { type: String },
    twitter: { type: String },
    linkedin: { type: String },
    instagram: { type: String },
    passwordResetToken: { type: String, select: 0 },
    passwordResetExpires: { type: Date, select: 0 },
    googleId: { type: String, unique: true, sparse: true, select: 0 } // Added for Google OAuth
  },
  { timestamps: true }
);

userSchema.pre('save', async function (next) {
  // Only hash password if it's present and has been modified (or is new)
  if (this.password && this.isModified('password')) {
    this.password = await hashPassword(this.password);
  }
  next();
});

const User = model<IUser>('user', userSchema);
export default User;
