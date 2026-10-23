import dotenv from "dotenv";
dotenv.config();

import mongoose from "mongoose";
import bcrypt from "bcrypt";
import { User, deriveInitials, UserRole } from "../models/User";

export interface ProvisionInput {
  email: string;
  password: string;
  name?: string;
  role?: UserRole;
  department?: string;
  allowUpdate?: boolean;
}

export function validateProvisionInput(input: ProvisionInput): { valid: boolean; error?: string } {
  if (!input.email || typeof input.email !== "string" || !/^\S+@\S+\.\S+$/.test(input.email)) {
    return { valid: false, error: "Invalid email address format." };
  }
  if (!input.password || typeof input.password !== "string" || input.password.length < 4 || input.password.length > 72) {
    return { valid: false, error: "Password must be between 4 and 72 characters." };
  }
  if (!input.allowUpdate && (!input.name || typeof input.name !== "string" || input.name.trim().length < 2)) {
    return { valid: false, error: "Name must be at least 2 characters." };
  }
  if (input.role && input.role !== "professor" && input.role !== "student") {
    return { valid: false, error: "Role must be either 'professor' or 'student'." };
  }
  return { valid: true };
}

export async function main() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error("Error: MONGODB_URI is not set in environment.");
    process.exit(1);
  }

  // Parse command line arguments: --role, --email, --name, --password, --department, --update, --reset-password
  const args = process.argv.slice(2);
  const getArg = (flag: string): string | undefined => {
    const idx = args.indexOf(flag);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : undefined;
  };
  const hasFlag = (flag: string): boolean => args.includes(flag);

  const allowUpdate = hasFlag("--update") || hasFlag("--reset-password");
  const role = (getArg("--role") || "professor") as UserRole;
  const email = getArg("--email");
  const name = getArg("--name");
  const password = getArg("--password");
  const department = getArg("--department") || (role === "professor" ? "Computer Science" : "General");

  if (!email || !password || (!name && !allowUpdate)) {
    console.log(
      "Usage:\n  npx tsx src/scripts/create-user.ts --email <email> --password <password> [--name <name>] [--role <professor|student>] [--department <dept>] [--update|--reset-password]\n"
    );
    console.log("Examples:");
    console.log(
      '  Create new user:\n    npx tsx src/scripts/create-user.ts --role professor --email professor@blocksubmit.edu --name "Dr. Ananya Rao" --password "your-password"\n'
    );
    console.log(
      '  Reset existing user password:\n    npx tsx src/scripts/create-user.ts --email professor@blocksubmit.edu --password "your-new-password" --update\n'
    );
    process.exit(1);
  }

  const validation = validateProvisionInput({
    email,
    password,
    name,
    role,
    department,
    allowUpdate,
  });

  if (!validation.valid) {
    console.error(`Error: ${validation.error}`);
    process.exit(1);
  }

  console.log("Connecting to database...");
  await mongoose.connect(uri);

  const normalizedEmail = email.toLowerCase().trim();
  const existing = await User.findOne({ email: normalizedEmail }).select("+passwordHash");

  if (existing) {
    if (!allowUpdate) {
      console.log(
        `User '${normalizedEmail}' already exists with role: '${existing.role}'. No changes made. (To update password, pass --update or --reset-password)`
      );
      await mongoose.disconnect();
      return;
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    existing.passwordHash = passwordHash;
    if (name && name.trim().length >= 2) {
      existing.name = name.trim();
      existing.initials = deriveInitials(existing.name);
    }
    if (getArg("--department")) {
      existing.department = department.trim();
    }
    if (getArg("--role") && (role === "professor" || role === "student")) {
      existing.role = role;
    }

    await existing.save();

    console.log(
      `Successfully updated credentials for ${existing.role} user:\n  Name: ${existing.name}\n  Email: ${existing.email}\n  Initials: ${existing.initials}\n  ID: ${existing._id}`
    );
    await mongoose.disconnect();
    return;
  }

  if (!name || name.trim().length < 2) {
    console.error("Error: Name must be at least 2 characters for a new user.");
    await mongoose.disconnect();
    process.exit(1);
  }

  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(password, saltRounds);
  const initials = deriveInitials(name);

  const user = await User.create({
    name: name.trim(),
    email: normalizedEmail,
    passwordHash,
    role,
    initials,
    department: department.trim(),
  });

  console.log(
    `Successfully provisioned ${role} user:\n  Name: ${user.name}\n  Email: ${user.email}\n  Initials: ${user.initials}\n  ID: ${user._id}`
  );

  await mongoose.disconnect();
}

const isMainModule = (): boolean => {
  if (!process.argv[1]) return false;
  return process.argv[1].endsWith("create-user.ts") || process.argv[1].endsWith("create-user.js");
};

if (isMainModule()) {
  main().catch(async (err) => {
    console.error("Failed to provision user:", err instanceof Error ? err.message : err);
    try {
      await mongoose.disconnect();
    } catch {}
    process.exit(1);
  });
}
