import { Router, Request, Response } from "express";
import { authenticateJWT } from "../middleware/auth";
import { Submission } from "../models/Submission";
import { Assignment } from "../models/Assignment";

export const activityRouter = Router();

export interface ActivityItem {
  id: string;
  type: "assignment" | "submission" | "verification" | "warning";
  title: string;
  detail: string;
  timestamp: string;
}

// GET /api/activities - Feed of recent coursework and integrity activities
activityRouter.get("/", authenticateJWT, async (req: Request, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const activities: ActivityItem[] = [];
    const isStudent = req.user.role === "student";

    // Submissions query scoped to authenticated student if role is student
    const submissionFilter = isStudent ? { studentRef: req.user._id } : {};
    const recentSubmissions = await Submission.find(submissionFilter)
      .sort({ submittedAt: -1 })
      .limit(isStudent ? 10 : 5);

    for (const sub of recentSubmissions) {
      if (sub.status === "VERIFIED") {
        activities.push({
          id: `act-ver-${sub._id.toString()}`,
          type: "verification",
          title: "Document verified",
          detail: `${sub.student.name} · ${sub.assignmentTitle}`,
          timestamp: sub.updatedAt ? sub.updatedAt.toISOString() : sub.submittedAt.toISOString(),
        });
      } else if (sub.status === "TAMPERED") {
        activities.push({
          id: `act-tam-${sub._id.toString()}`,
          type: "warning",
          title: "Integrity mismatch detected",
          detail: `${sub.student.name} · ${sub.assignmentTitle}`,
          timestamp: sub.updatedAt ? sub.updatedAt.toISOString() : sub.submittedAt.toISOString(),
        });
      } else {
        activities.push({
          id: `act-sub-${sub._id.toString()}`,
          type: "submission",
          title: "Submission received",
          detail: `${sub.student.name} · ${sub.assignmentTitle}`,
          timestamp: sub.submittedAt.toISOString(),
        });
      }
    }

    // Fetch recent assignments
    const recentAssignments = await Assignment.find().sort({ createdAt: -1 }).limit(3);
    for (const a of recentAssignments) {
      activities.push({
        id: `act-asg-${a._id.toString()}`,
        type: "assignment",
        title: "Assignment created",
        detail: a.title,
        timestamp: a.createdAt.toISOString(),
      });
    }

    // Sort combined activities newest first
    activities.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    res.status(200).json(activities);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to retrieve activity feed";
    res.status(500).json({ message });
  }
});
