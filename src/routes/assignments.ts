import { Router, Request, Response } from "express";
import mongoose from "mongoose";
import { Assignment, generateAssignmentCode, AssignmentStatus } from "../models/Assignment";
import { Submission } from "../models/Submission";
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
  submissionId?: string | null;
}

export function resolveEffectiveStatus(assignment: { status: AssignmentStatus; deadline: Date | string | null }): AssignmentStatus {
  if (assignment.status === "ACTIVE" && assignment.deadline) {
    const deadlineTime = new Date(assignment.deadline).getTime();
    if (!isNaN(deadlineTime) && deadlineTime <= Date.now()) {
      return "CLOSED";
    }
  }
  return assignment.status;
}

// GET /api/assignments - Authenticated users can list assignments
assignmentRouter.get("/", authenticateJWT, async (req: Request, res: Response): Promise<void> => {
  try {
    const assignments = await Assignment.find().sort({ createdAt: -1 });
    const userRole = req.user?.role;
    const studentId = req.user?._id;

    // For student requests, retrieve their existing submissions to accurately report submission status and submissionId
    const studentSubmissionMap = new Map<string, { status: string; submissionId: string }>();
    if (userRole === "student" && studentId) {
      const studentSubmissions = await Submission.find({ studentRef: studentId })
        .sort({ submittedAt: -1 })
        .select("submissionId assignmentId assignmentRef status");

      for (const sub of studentSubmissions) {
        const idKey = sub.assignmentId || sub.assignmentRef?.toString();
        if (idKey && !studentSubmissionMap.has(idKey)) {
          studentSubmissionMap.set(idKey, {
            status: sub.status,
            submissionId: sub.submissionId || sub._id.toString(),
          });
        }
      }
    }

    const formatted: AssignmentResponse[] = assignments.map((a) => {
      const json = a.toJSON() as unknown as AssignmentResponse;
      json.status = resolveEffectiveStatus(a);
      if (userRole === "student") {
        const matching =
          studentSubmissionMap.get(json.id) ||
          studentSubmissionMap.get(a._id.toString());
        json.submissionStatus = matching?.status || "NOT_SUBMITTED";
        json.submissionId = matching?.submissionId || null;
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
    json.status = resolveEffectiveStatus(assignment);
    if (req.user?.role === "student" && req.user?._id) {
      const studentSub = await Submission.findOne({
        studentRef: req.user._id,
        $or: [{ assignmentId: id }, { assignmentRef: assignment._id }],
      }).sort({ submittedAt: -1 });

      json.submissionStatus = studentSub?.status || "NOT_SUBMITTED";
      json.submissionId = studentSub ? (studentSub.submissionId || studentSub._id.toString()) : null;
    }

    res.status(200).json(json);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to retrieve assignment";
    res.status(500).json({ message });
  }
});

// Handler for updating an existing assignment (PUT & PATCH)
async function handleUpdateAssignment(req: Request, res: Response): Promise<void> {
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

    const { title, description, deadline, status, requirements } = req.body;

    if (title !== undefined) {
      if (typeof title !== "string" || title.trim().length < 3) {
        res.status(400).json({ message: "Assignment title must be at least 3 characters." });
        return;
      }
      if (title.trim().length > 150) {
        res.status(400).json({ message: "Assignment title must not exceed 150 characters." });
        return;
      }
      assignment.title = title.trim();
    }

    if (description !== undefined) {
      if (typeof description !== "string" || description.trim().length < 5) {
        res.status(400).json({ message: "Assignment description must be at least 5 characters." });
        return;
      }
      if (description.trim().length > 5000) {
        res.status(400).json({ message: "Assignment description must not exceed 5000 characters." });
        return;
      }
      assignment.description = description.trim();
    }

    if (deadline !== undefined) {
      const parsedDeadline = new Date(deadline);
      if (isNaN(parsedDeadline.getTime())) {
        res.status(400).json({ message: "Invalid deadline format. Must be a valid date." });
        return;
      }
      assignment.deadline = parsedDeadline;

      // If deadline is extended into the future and assignment was CLOSED, automatically reactivate to ACTIVE
      if (parsedDeadline.getTime() > Date.now()) {
        if (assignment.status === "CLOSED") {
          assignment.status = "ACTIVE";
        }
      } else {
        // Deadline is set in the past
        if (assignment.status === "ACTIVE") {
          assignment.status = "CLOSED";
        }
      }
    }

    if (status !== undefined) {
      const validStatuses: AssignmentStatus[] = ["ACTIVE", "CLOSED", "ARCHIVED", "DRAFT"];
      if (!validStatuses.includes(status)) {
        res.status(400).json({ message: "Status must be ACTIVE, CLOSED, ARCHIVED, or DRAFT." });
        return;
      }
      if (status === "ACTIVE" && new Date(assignment.deadline).getTime() <= Date.now()) {
        res.status(400).json({
          message: "Cannot activate an assignment whose deadline has already passed. Please extend the deadline first.",
        });
        return;
      }
      assignment.status = status;
    }

    if (requirements !== undefined) {
      if (Array.isArray(requirements)) {
        assignment.requirements = requirements.filter(
          (r) => typeof r === "string" && r.trim().length > 0
        );
      }
    }

    await assignment.save();

    const json = assignment.toJSON() as unknown as AssignmentResponse;
    json.status = resolveEffectiveStatus(assignment);
    res.status(200).json(json);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to update assignment";
    res.status(500).json({ message });
  }
}

// PUT /api/assignments/:id - Professors can edit an existing assignment
assignmentRouter.put("/:id", authenticateJWT, requireRole("professor"), handleUpdateAssignment);

// PATCH /api/assignments/:id - Professors can partially update an existing assignment
assignmentRouter.patch("/:id", authenticateJWT, requireRole("professor"), handleUpdateAssignment);

// DELETE /api/assignments/:id - Safe deletion / archiving rule
assignmentRouter.delete(
  "/:id",
  authenticateJWT,
  requireRole("professor"),
  async (req: Request, res: Response): Promise<void> => {
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

      // Enforce safe deletion rule: if ANY submissions exist, block permanent deletion
      const submissionCount = await Submission.countDocuments({
        $or: [{ assignmentId: id }, { assignmentRef: assignment._id }],
      });

      if (submissionCount > 0 || (assignment.submissionCount && assignment.submissionCount > 0)) {
        res.status(409).json({
          message:
            "Cannot delete an assignment with existing submissions. Archive or close the assignment instead to preserve student submission records and integrity proofs.",
          hasSubmissions: true,
          submissionCount: submissionCount || assignment.submissionCount,
        });
        return;
      }

      // Zero submissions: safe to permanently delete assignment record
      await Assignment.findByIdAndDelete(assignment._id);

      res.status(200).json({
        message: "Assignment deleted successfully.",
        id: assignment._id.toString(),
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to delete assignment";
      res.status(500).json({ message });
    }
  }
);
