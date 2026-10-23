import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { User, UserRole } from "../models/User";

export interface TokenPayload {
  id: string;
  email: string;
  role: UserRole;
}

export async function authenticateJWT(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ message: "Unauthorized: Missing or invalid authorization token" });
    return;
  }

  const token = authHeader.split(" ")[1];
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    res.status(500).json({ message: "Server configuration error: JWT_SECRET not configured" });
    return;
  }

  try {
    const decoded = jwt.verify(token, secret) as TokenPayload;
    const user = await User.findById(decoded.id);

    if (!user) {
      res.status(401).json({ message: "Unauthorized: User account not found" });
      return;
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: "Unauthorized: Token expired or invalid" });
  }
}

export function requireRole(allowedRole: UserRole) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ message: "Unauthorized: Authentication required" });
      return;
    }

    if (req.user.role !== allowedRole) {
      res.status(403).json({
        message: `Forbidden: This operation requires the ${allowedRole} role`,
      });
      return;
    }

    next();
  };
}
