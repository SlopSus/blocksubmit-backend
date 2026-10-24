import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { Server } from "node:http";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import { app } from "../src/app";
import { User } from "../src/models/User";
import { Submission } from "../src/models/Submission";
import { Assignment } from "../src/models/Assignment";

describe("GET /api/activities - Activity Feed Scoping & Privacy", () => {
  let server: Server;
  let baseUrl: string;
  const testSecret = "test-jwt-secret-for-activities-tests";

  const studentAId = new mongoose.Types.ObjectId();
  const studentBId = new mongoose.Types.ObjectId();
  const professorId = new mongoose.Types.ObjectId();

  let studentAToken: string;
  let studentBToken: string;
  let professorToken: string;

  const originalUserFindById = User.findById;
  const originalSubmissionFind = Submission.find;
  const originalAssignmentFind = Assignment.find;

  // Mock submission documents
  const submissionA = {
    _id: new mongoose.Types.ObjectId(),
    status: "VERIFIED",
    student: {
      id: studentAId.toString(),
      name: "Aarav Menon",
      email: "aarav@blocksubmit.edu",
      initials: "AM",
    },
    studentRef: studentAId,
    assignmentTitle: "Distributed Systems Research Paper",
    submittedAt: new Date("2026-10-24T08:00:00.000Z"),
    updatedAt: new Date("2026-10-24T08:30:00.000Z"),
  };

  const submissionB = {
    _id: new mongoose.Types.ObjectId(),
    status: "TAMPERED",
    student: {
      id: studentBId.toString(),
      name: "Rohan Shah",
      email: "rohan@blocksubmit.edu",
      initials: "RS",
    },
    studentRef: studentBId,
    assignmentTitle: "Cryptographic Hash Collision Analysis",
    submittedAt: new Date("2026-10-24T09:00:00.000Z"),
    updatedAt: new Date("2026-10-24T09:15:00.000Z"),
  };

  const mockAssignment = {
    _id: new mongoose.Types.ObjectId(),
    title: "Smart Contract Security Audit",
    createdAt: new Date("2026-10-24T07:00:00.000Z"),
  };

  before(() => {
    process.env.JWT_SECRET = testSecret;

    studentAToken = jwt.sign(
      { id: studentAId.toString(), email: "aarav@blocksubmit.edu", role: "student" },
      testSecret,
      { expiresIn: "1h" }
    );
    studentBToken = jwt.sign(
      { id: studentBId.toString(), email: "rohan@blocksubmit.edu", role: "student" },
      testSecret,
      { expiresIn: "1h" }
    );
    professorToken = jwt.sign(
      { id: professorId.toString(), email: "prof@blocksubmit.edu", role: "professor" },
      testSecret,
      { expiresIn: "1h" }
    );

    // Mock User.findById for authenticateJWT middleware
    User.findById = ((id: any) => {
      const idStr = id ? id.toString() : "";
      if (idStr === studentAId.toString()) {
        return Promise.resolve({
          _id: studentAId,
          role: "student",
          email: "aarav@blocksubmit.edu",
          name: "Aarav Menon",
          initials: "AM",
        });
      }
      if (idStr === studentBId.toString()) {
        return Promise.resolve({
          _id: studentBId,
          role: "student",
          email: "rohan@blocksubmit.edu",
          name: "Rohan Shah",
          initials: "RS",
        });
      }
      if (idStr === professorId.toString()) {
        return Promise.resolve({
          _id: professorId,
          role: "professor",
          email: "prof@blocksubmit.edu",
          name: "Dr. Ananya Rao",
          initials: "AR",
        });
      }
      return Promise.resolve(null);
    }) as any;

    // Mock Submission.find to filter according to caller's studentRef
    Submission.find = ((filter?: any) => {
      let results: any[] = [];
      if (filter && filter.studentRef) {
        const targetId = filter.studentRef.toString();
        if (targetId === studentAId.toString()) {
          results = [submissionA];
        } else if (targetId === studentBId.toString()) {
          results = [submissionB];
        }
      } else {
        // Professor or unscoped query returns all submissions
        results = [submissionB, submissionA];
      }

      return {
        sort: () => ({
          limit: (n: number) => Promise.resolve(results.slice(0, n)),
        }),
      } as any;
    }) as any;

    // Mock Assignment.find to return coursework announcements
    Assignment.find = (() => {
      return {
        sort: () => ({
          limit: (n: number) => Promise.resolve([mockAssignment].slice(0, n)),
        }),
      } as any;
    }) as any;

    return new Promise((resolve) => {
      server = app.listen(0, () => {
        const addr = server.address();
        if (addr && typeof addr === "object") {
          baseUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });
  });

  after(() => {
    User.findById = originalUserFindById;
    Submission.find = originalSubmissionFind;
    Assignment.find = originalAssignmentFind;

    return new Promise((resolve) => {
      server.close(() => resolve());
    });
  });

  it("GET /api/activities rejects unauthenticated requests with 401", async () => {
    const res = await fetch(`${baseUrl}/api/activities`);
    assert.strictEqual(res.status, 401);
  });

  it("GET /api/activities for Student A returns ONLY Student A's activity, hiding Student B's name, assignments, and tampering alerts", async () => {
    const res = await fetch(`${baseUrl}/api/activities`, {
      headers: { Authorization: `Bearer ${studentAToken}` },
    });

    assert.strictEqual(res.status, 200);
    const activities = await res.json();
    assert.ok(Array.isArray(activities));

    // Confirm Student A sees their own verified submission activity
    const studentAActivity = activities.find(
      (a: any) => a.detail && a.detail.includes("Aarav Menon")
    );
    assert.ok(studentAActivity, "Student A should see their own submission activity");
    assert.strictEqual(studentAActivity.type, "verification");
    assert.strictEqual(studentAActivity.title, "Document verified");

    // PROOF OF PRIVACY: Confirm Student A does NOT see Student B's name
    const mentionsStudentB = activities.some(
      (a: any) => a.detail && a.detail.includes("Rohan Shah")
    );
    assert.strictEqual(mentionsStudentB, false, "Student A MUST NOT see Student B's name");

    // PROOF OF PRIVACY: Confirm Student A does NOT see Student B's assignment submission
    const mentionsStudentBAssignment = activities.some(
      (a: any) => a.detail && a.detail.includes("Cryptographic Hash Collision Analysis")
    );
    assert.strictEqual(
      mentionsStudentBAssignment,
      false,
      "Student A MUST NOT see Student B's assignment submission"
    );

    // PROOF OF PRIVACY: Confirm Student A does NOT see Student B's tampering alert
    const hasTamperingWarning = activities.some((a: any) => a.type === "warning");
    assert.strictEqual(
      hasTamperingWarning,
      false,
      "Student A MUST NOT see tampering warnings belonging to another student"
    );

    // Confirm generic assignment announcement is visible
    const assignmentActivity = activities.find((a: any) => a.type === "assignment");
    assert.ok(assignmentActivity, "Assignment announcements should remain visible");
  });

  it("GET /api/activities for Professor returns institution-wide activity feed including all students' submissions and warnings", async () => {
    const res = await fetch(`${baseUrl}/api/activities`, {
      headers: { Authorization: `Bearer ${professorToken}` },
    });

    assert.strictEqual(res.status, 200);
    const activities = await res.json();
    assert.ok(Array.isArray(activities));

    // Professor sees Student A's verification
    const studentAActivity = activities.find(
      (a: any) => a.detail && a.detail.includes("Aarav Menon")
    );
    assert.ok(studentAActivity, "Professor must see Student A's activity");
    assert.strictEqual(studentAActivity.type, "verification");

    // Professor sees Student B's tampering alert
    const studentBWarning = activities.find(
      (a: any) => a.detail && a.detail.includes("Rohan Shah") && a.type === "warning"
    );
    assert.ok(studentBWarning, "Professor must see Student B's tampering warning");
    assert.strictEqual(studentBWarning.title, "Integrity mismatch detected");

    // Professor sees coursework assignment created
    const assignmentActivity = activities.find((a: any) => a.type === "assignment");
    assert.ok(assignmentActivity, "Professor must see assignment creation events");
  });
});
