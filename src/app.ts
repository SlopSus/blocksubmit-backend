import express, { Request, Response } from "express";
import cors from "cors";
import helmet from "helmet";

export const app = express();

// Basic security and parsing middleware
app.use(helmet());
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
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
