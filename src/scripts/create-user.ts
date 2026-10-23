import dotenv from "dotenv";
dotenv.config();

import mongoose from "mongoose";
import bcrypt from "bcrypt";
import { User, deriveInitials, UserRole } from "../models/User";

async function main() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error("Error: MONGODB_URI is not set in environment.");
    process.exit(1);
  }

  // Parse command line arguments: --role, --email, --name, --password, --department
  const args = process.argv.slice(2);
  const getArg = (flag: string): string | undefined => {
    const idx = args.indexOf(flag);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : undefined;
  };

  const role = (getArg("--role") || "professor") as UserRole;
  const email = getArg("--email");
  const name = getArg("--name");
  const password = getArg("--password");
  const department = getArg("--department") || (role === "professor" ? "Computer Science" : "General");

  if (!email || !name || !password) {
    console.log(
      "Usage:\n  npx tsx src/scripts/create-user.ts --role <professor|student> --email <email> --name <name> --password <password> [--department <dept>]\n"
    );
    console.log("Example:");
    console.log(
      '  npx tsx src/scripts/create-user.ts --role professor --email professor@blocksubmit.edu --name "Dr. Ananya Rao" --password "your-secure-password"\n'
    );
    process.exit(1);
  }

  if (role !== "professor" && role !== "student") {
    console.error("Error: Role must be either 'professor' or 'student'.");
    process.exit(1);
  }

  if (password.length < 4 || password.length > 72) {
    console.error("Error: Password must be between 4 and 72 characters.");
    process.exit(1);
  }

  if (!/^\S+@\S+\.\S+$/.test(email)) {
    console.error("Error: Invalid email address format.");
    process.exit(1);
  }

  console.log("Connecting to database...");
  await mongoose.connect(uri);

  const normalizedEmail = email.toLowerCase().trim();
  const existing = await User.findOne({ email: normalizedEmail });

  if (existing) {
    console.log(`User '${normalizedEmail}' already exists with role: '${existing.role}'. No changes made.`);
    await mongoose.disconnect();
    return;
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

main().catch((err) => {
  console.error("Failed to provision user:", err instanceof Error ? err.message : err);
  process.exit(1);
});
