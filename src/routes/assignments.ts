import { Router, Request, Response } from "express";
import mongoose from "mongoose";
import { Assignment, generateAssignmentCode, AssignmentStatus } from "../models/Assignment";
import { authenticateJWT, requireRole } from "../middleware/auth";

export const assignmentRouter = Router();

export interface AssignmentResponse {
  id: string;
  title: string;
  code: string;
  description: string;
  deadline: string | null;
  status: AssignmentStatus;
  submissionCount: number;
  requirements: string[];
  createdAt: string | null;
  submissionStatus?: string;
}

// GET /api/assignments - Authenticated users can list assignments
assignmentRouter.get("/", authenticateJWT, async (req: Request, res: Response): Promise<void> => {
  try {
    const assignments = await Assignment.find().sort({ createdAt: -1 });
    const userRole = req.user?.role;

    const formatted: AssignmentResponse[] = assignments.map((a) => {
      const json = a.toJSON() as unknown as AssignmentResponse;
      if (userRole === "student") {
        json.submissionStatus = "NOT_SUBMITTED";
      }
      return json;
    });

    res.status(200).json(formatted);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to retrieve assignments";
    res.status(500).json({ message });
  }
});

// POST /api/assignments - Only professors can create coursework assignments
assignmentRouter.post(
  "/",
  authenticateJWT,
  requireRole("professor"),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { title, description, deadline, code, requirements } = req.body;

      if (!title || typeof title !== "string" || title.trim().length < 3) {
        res.status(400).json({ message: "Assignment title must be at least 3 characters." });
        return;
      }

      if (!description || typeof description !== "string" || description.trim().length < 5) {
        res.status(400).json({ message: "Assignment description must be at least 5 characters." });
        return;
      }

      if (!deadline) {
        res.status(400).json({ message: "Submission deadline is required." });
        return;
      }

      const parsedDeadline = new Date(deadline);
      if (isNaN(parsedDeadline.getTime())) {
        res.status(400).json({ message: "Invalid deadline format. Must be a valid date." });
        return;
      }

      if (parsedDeadline.getTime() <= Date.now()) {
        res.status(400).json({ message: "Deadline must be a future date and time." });
        return;
      }

      const assignmentCode =
        code && typeof code === "string" && code.trim().length > 0
          ? code.trim().toUpperCase()
          : generateAssignmentCode();

      const assignmentRequirements =
        Array.isArray(requirements) && requirements.length > 0
          ? requirements.filter((r) => typeof r === "string" && r.trim().length > 0)
          : ["PDF format only", "Maximum file size: 10 MB"];

      const assignment = await Assignment.create({
        title: title.trim(),
        code: assignmentCode,
        description: description.trim(),
        deadline: parsedDeadline,
        status: "ACTIVE",
        submissionCount: 0,
        requirements: assignmentRequirements,
        createdBy: req.user!._id,
      });

      res.status(201).json(assignment.toJSON());
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to create assignment";
      res.status(500).json({ message });
    }
  }
);

// GET /api/assignments/:id - Authenticated users can fetch a specific assignment
assignmentRouter.get("/:id", authenticateJWT, async (req: Request, res: Response): Promise<void> => {
  try {
    const rawId = req.params.id;
    const id = Array.isArray(rawId) ? rawId[0] : String(rawId);

    if (!mongoose.Types.ObjectId.isValid(id)) {
      res.status(404).json({ message: "Assignment not found." });
      return;
    }

    const assignment = await Assignment.findById(id);
    if (!assignment) {
      res.status(404).json({ message: "Assignment not found." });
      return;
    }

    const json = assignment.toJSON() as unknown as AssignmentResponse;
    if (req.user?.role === "student") {
      json.submissionStatus = "NOT_SUBMITTED";
    }

    res.status(200).json(json);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to retrieve assignment";
    res.status(500).json({ message });
  }
});
