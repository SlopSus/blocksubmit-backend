import { Router, Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { User, deriveInitials, UserRole } from "../models/User";
import { authenticateJWT, TokenPayload } from "../middleware/auth";

export const authRouter = Router();

// POST /api/auth/login
authRouter.post("/login", async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    if (!email || typeof email !== "string" || !/^\S+@\S+\.\S+$/.test(email)) {
      res.status(400).json({ message: "A valid email address is required." });
      return;
    }

    if (!password || typeof password !== "string" || password.length < 4 || password.length > 72) {
      res.status(400).json({ message: "Password must be between 4 and 72 characters." });
      return;
    }

    // Explicitly select passwordHash which is hidden by default
    const user = await User.findOne({ email: email.toLowerCase().trim() }).select("+passwordHash");
    if (!user) {
      // Use generic error message to prevent user enumeration
      res.status(401).json({ message: "Invalid email or password." });
      return;
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      // Use identical generic error message
      res.status(401).json({ message: "Invalid email or password." });
      return;
    }

    const secret = process.env.JWT_SECRET;
    if (!secret || secret.length < 16) {
      res.status(500).json({ message: "Server error: JWT_SECRET is not configured properly." });
      return;
    }

    const payload: TokenPayload = {
      id: user._id.toString(),
      email: user.email,
      role: user.role,
    };

    const token = jwt.sign(payload, secret, { expiresIn: "24h" });

    // user.toJSON() automatically strips passwordHash and normalizes _id to id
    res.status(200).json({
      token,
      user: user.toJSON(),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal login error";
    res.status(500).json({ message });
  }
});

// GET /api/auth/me
authRouter.get("/me", authenticateJWT, (req: Request, res: Response): void => {
  if (!req.user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  res.status(200).json(req.user.toJSON());
});

// POST /api/auth/register
authRouter.post("/register", async (req: Request, res: Response): Promise<void> => {
  try {
    const { name, email, password, role, department, initials, inviteCode } = req.body;

    if (!name || typeof name !== "string" || name.trim().length < 2) {
      res.status(400).json({ message: "Name must be at least 2 characters." });
      return;
    }

    if (!email || typeof email !== "string" || !/^\S+@\S+\.\S+$/.test(email)) {
      res.status(400).json({ message: "A valid email address is required." });
      return;
    }

    if (!password || typeof password !== "string" || password.length < 4 || password.length > 72) {
      res.status(400).json({ message: "Password must be between 4 and 72 characters." });
      return;
    }

    const requestedRole: UserRole = role || "student";

    if (requestedRole !== "professor" && requestedRole !== "student") {
      res.status(400).json({ message: "Role must be either 'professor' or 'student'." });
      return;
    }

    // Privilege escalation protection:
    // Only students can publicly self-register without an invite code.
    // Registering as a professor via the public API requires a valid PROFESSOR_INVITE_CODE.
    if (requestedRole === "professor") {
      const codeProvided = inviteCode || req.headers["x-professor-invite-code"];
      const configuredCode = process.env.PROFESSOR_INVITE_CODE;

      if (!configuredCode || !codeProvided || codeProvided !== configuredCode) {
        res.status(403).json({
          message:
            "Forbidden: A valid professor invite code is required to register with the professor role.",
        });
        return;
      }
    }

    const normalizedEmail = email.toLowerCase().trim();
    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      res.status(409).json({ message: "A user with this email address already exists." });
      return;
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const userInitials =
      initials && typeof initials === "string" && initials.trim().length > 0
        ? initials.trim().toUpperCase()
        : deriveInitials(name);

    const userDept =
      department && typeof department === "string" && department.trim().length > 0
        ? department.trim()
        : "General";

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      passwordHash,
      role: requestedRole,
      initials: userInitials,
      department: userDept,
    });

    const secret = process.env.JWT_SECRET;
    if (!secret || secret.length < 16) {
      res.status(500).json({ message: "Server error: JWT_SECRET is not configured properly." });
      return;
    }

    const payload: TokenPayload = {
      id: user._id.toString(),
      email: user.email,
      role: user.role,
    };

    const token = jwt.sign(payload, secret, { expiresIn: "24h" });

    res.status(201).json({
      token,
      user: user.toJSON(),
    });
  } catch (error: unknown) {
    // Handle concurrent duplicate email race conditions from MongoDB unique index
    if (error && typeof error === "object" && "code" in error && (error as { code: number }).code === 11000) {
      res.status(409).json({ message: "A user with this email address already exists." });
      return;
    }

    const message = error instanceof Error ? error.message : "Internal registration error";
    res.status(500).json({ message });
  }
});
