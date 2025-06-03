import { HydratedDocument } from 'mongoose';
import { IUser } from '../../modules/user/user.interface'; // Adjust path if necessary

// Define a type for the user object that Passport will handle, including the optional token
export type PassportUserType = HydratedDocument<IUser> & { token?: string };

declare global {
  namespace Express {
    // eslint-disable-next-line @typescript-eslint/no-empty-interface
    export interface User extends PassportUserType {}
  }
}