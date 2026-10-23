import express, { Request, Response } from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
dotenv.config();

import { authRouter } from "./routes/auth";
import { assignmentRouter } from "./routes/assignments";
import { submissionRouter } from "./routes/submissions";
import { activityRouter } from "./routes/activities";

export const app = express();

// Basic security and parsing middleware
app.use(helmet());

const getAllowedOrigins = (): string[] => {
  const origins = ["http://localhost:8080", "http://localhost:3000"];
  const configured = process.env.FRONTEND_URL;
  if (configured) {
    const urls = configured.split(",").map((s) => s.trim()).filter(Boolean);
    for (const url of urls) {
      if (!origins.includes(url)) {
        origins.push(url);
      }
    }
  }
  return origins;
};

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. mobile apps, curl, server-to-server)
      if (!origin) {
        return callback(null, true);
      }
      const allowed = getAllowedOrigins();
      if (allowed.includes(origin)) {
        return callback(null, true);
      }
      return callback(null, false);
    },
    credentials: true,
  })
);
app.use(express.json());

// Minimal health check endpoint
app.get("/api/health", (_req: Request, res: Response) => {
  res.status(200).json({
    status: "ok",
    timestamp: new Date().toISOString(),
    service: "blocksubmit-backend",
    version: "1.0.0",
  });
});

// Mount domain routes under /api
app.use("/api/auth", authRouter);
app.use("/api/assignments", assignmentRouter);
app.use("/api/submissions", submissionRouter);
app.use("/api/activities", activityRouter);

// 404 handler for unhandled /api routes
app.use("/api", (_req: Request, res: Response) => {
  res.status(404).json({ message: "API endpoint not found" });
});
