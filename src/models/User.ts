import mongoose, { Document, Schema } from "mongoose";
import bcrypt from "bcrypt";

export type UserRole = "professor" | "student";

export interface IUser extends Document {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  role: UserRole;
  initials: string;
  department: string;
  createdAt: Date;
  updatedAt: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

export function deriveInitials(name: string): string {
  const titles = ["dr.", "dr", "prof.", "prof", "mr.", "mr", "mrs.", "mrs", "ms.", "ms"];
  const parts = name.trim().split(/\s+/).filter(Boolean);
  const filtered = parts.filter((p) => !titles.includes(p.toLowerCase()));
  const effectiveParts = filtered.length > 0 ? filtered : parts;

  if (effectiveParts.length === 0) return "U";
  if (effectiveParts.length === 1) return effectiveParts[0].slice(0, 2).toUpperCase();
  return (effectiveParts[0][0] + effectiveParts[effectiveParts.length - 1][0]).toUpperCase();
}

const userSchema = new Schema<IUser>(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      minlength: [2, "Name must be at least 2 characters"],
      maxlength: [100, "Name must not exceed 100 characters"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, "Please provide a valid email address"],
    },
    passwordHash: {
      type: String,
      required: [true, "Password is required"],
      select: false, // Hidden by default in all Mongoose queries
    },
    role: {
      type: String,
      enum: {
        values: ["professor", "student"],
        message: "Role must be either professor or student",
      },
      required: [true, "Role is required"],
    },
    initials: {
      type: String,
      required: [true, "Initials are required"],
      trim: true,
      uppercase: true,
      maxlength: 4,
    },
    department: {
      type: String,
      required: [true, "Department is required"],
      trim: true,
      default: "General",
      maxlength: [100, "Department must not exceed 100 characters"],
    },
  },
  {
    timestamps: true,
    toJSON: {
      transform(_doc, ret: Record<string, unknown>) {
        return {
          id: (ret._id as mongoose.Types.ObjectId).toString(),
          name: ret.name,
          email: ret.email,
          role: ret.role,
          initials: ret.initials,
          department: ret.department,
          createdAt: ret.createdAt ? new Date(ret.createdAt as string | number | Date).toISOString() : undefined,
        };
      },
    },
  }
);

userSchema.methods.comparePassword = async function (
  candidatePassword: string
): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.passwordHash);
};

export const User = mongoose.model<IUser>("User", userSchema);
