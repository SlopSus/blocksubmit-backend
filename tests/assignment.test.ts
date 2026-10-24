import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { Server } from "node:http";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import { app } from "../src/app";
import { User } from "../src/models/User";
import { Assignment, generateAssignmentCode } from "../src/models/Assignment";
import { Submission } from "../src/models/Submission";
import { resolveEffectiveStatus } from "../src/routes/assignments";

describe("Assignment Model & Logic", () => {
  it("generates a valid course code with CS prefix", () => {
    const code = generateAssignmentCode();
    assert.match(code, /^CS-\d{3}$/);
  });

  it("ensures Assignment toJSON formats dates as ISO strings and normalizes id", () => {
    const fakeObjectId = new mongoose.Types.ObjectId();
    const fakeUserId = new mongoose.Types.ObjectId();
    const deadline = new Date("2026-12-31T23:59:59.000Z");

    const mockAssignment = new Assignment({
      _id: fakeObjectId,
      title: "Consensus Protocols in Distributed Systems",
      code: "CS-402",
      description: "Analyze PBFT, Raft, and PoW consensus mechanisms.",
      deadline,
      status: "ACTIVE",
      submissionCount: 0,
      requirements: ["PDF format only", "Maximum file size: 10 MB"],
      createdBy: fakeUserId,
    });

    const json = mockAssignment.toJSON();
    assert.strictEqual(json.id, fakeObjectId.toString());
    assert.strictEqual(json.title, "Consensus Protocols in Distributed Systems");
    assert.strictEqual(json.code, "CS-402");
    assert.strictEqual(json.deadline, deadline.toISOString());
    assert.strictEqual(json.status, "ACTIVE");
    assert.strictEqual(json.submissionCount, 0);
    assert.deepStrictEqual(json.requirements, ["PDF format only", "Maximum file size: 10 MB"]);
    assert.strictEqual((json as Record<string, unknown>)._id, undefined);
    assert.strictEqual((json as Record<string, unknown>).__v, undefined);
    assert.strictEqual((json as Record<string, unknown>).createdBy, undefined);
  });

  it("validates deadline logic", () => {
    const pastDate = new Date(Date.now() - 1000 * 60 * 60); // 1 hour ago
    assert.strictEqual(pastDate.getTime() < Date.now(), true);

    const futureDate = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7); // 7 days ahead
    assert.strictEqual(futureDate.getTime() > Date.now(), true);

    const invalidDate = new Date("not-a-real-date");
    assert.strictEqual(isNaN(invalidDate.getTime()), true);
  });
});

describe("Deadline & Status Lifecycle Logic (resolveEffectiveStatus)", () => {
  it("resolves ACTIVE status when deadline is in the future", () => {
    const futureDeadline = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();
    const effective = resolveEffectiveStatus({ status: "ACTIVE", deadline: futureDeadline });
    assert.strictEqual(effective, "ACTIVE");
  });

  it("resolves to CLOSED when deadline is in the past for an ACTIVE assignment", () => {
    const pastDeadline = new Date(Date.now() - 1000 * 60 * 60).toISOString();
    const effective = resolveEffectiveStatus({ status: "ACTIVE", deadline: pastDeadline });
    assert.strictEqual(effective, "CLOSED");
  });

  it("reactivates to ACTIVE when deadline is extended to the future", () => {
    // Initial expired assignment
    let deadline = new Date(Date.now() - 1000 * 60 * 60).toISOString();
    assert.strictEqual(resolveEffectiveStatus({ status: "ACTIVE", deadline }), "CLOSED");

    // Professor extends deadline into future
    deadline = new Date(Date.now() + 1000 * 60 * 60 * 48).toISOString();
    assert.strictEqual(resolveEffectiveStatus({ status: "ACTIVE", deadline }), "ACTIVE");
  });

  it("preserves ARCHIVED status regardless of deadline time", () => {
    const futureDeadline = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();
    const effective = resolveEffectiveStatus({ status: "ARCHIVED", deadline: futureDeadline });
    assert.strictEqual(effective, "ARCHIVED");
  });

  it("preserves DRAFT status regardless of deadline time", () => {
    const futureDeadline = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();
    const effective = resolveEffectiveStatus({ status: "DRAFT", deadline: futureDeadline });
    assert.strictEqual(effective, "DRAFT");
  });

  it("handles UTC ISO-8601 string timezone comparisons consistently with Date.now()", () => {
    // Test timezone parsing: UTC Z timestamp vs offset string
    const utcIso = "2026-10-24T12:00:00.000Z";
    const utcMillis = new Date(utcIso).getTime();
    assert.strictEqual(typeof utcMillis, "number");
    assert.strictEqual(isNaN(utcMillis), false);

    // Exact boundary test
    const now = Date.now();
    const boundaryPast = new Date(now - 1);
    const boundaryFuture = new Date(now + 1000);
    assert.strictEqual(resolveEffectiveStatus({ status: "ACTIVE", deadline: boundaryPast }), "CLOSED");
    assert.strictEqual(resolveEffectiveStatus({ status: "ACTIVE", deadline: boundaryFuture }), "ACTIVE");
  });
});

describe("Student Submission Status Mapping Logic", () => {
  it("defaults to NOT_SUBMITTED and submissionId null when student has not submitted assignment", () => {
    const studentSubmissionMap = new Map<string, { status: string; submissionId: string }>();
    const assignmentId = new mongoose.Types.ObjectId().toString();

    const matching = studentSubmissionMap.get(assignmentId);
    const submissionStatus = matching?.status || "NOT_SUBMITTED";
    const submissionId = matching?.submissionId || null;

    assert.strictEqual(submissionStatus, "NOT_SUBMITTED");
    assert.strictEqual(submissionId, null);
  });

  it("resolves to actual persisted status (PENDING, VERIFIED, TAMPERED) and submissionId when student has submitted", () => {
    const asg1 = new mongoose.Types.ObjectId().toString();
    const asg2 = new mongoose.Types.ObjectId().toString();
    const asg3 = new mongoose.Types.ObjectId().toString();

    const studentSubmissionMap = new Map<string, { status: string; submissionId: string }>([
      [asg1, { status: "VERIFIED", submissionId: "sub-verified-001" }],
      [asg2, { status: "PENDING", submissionId: "sub-pending-002" }],
      [asg3, { status: "TAMPERED", submissionId: "sub-tampered-003" }],
    ]);

    const match1 = studentSubmissionMap.get(asg1);
    assert.strictEqual(match1?.status || "NOT_SUBMITTED", "VERIFIED");
    assert.strictEqual(match1?.submissionId || null, "sub-verified-001");

    const match2 = studentSubmissionMap.get(asg2);
    assert.strictEqual(match2?.status || "NOT_SUBMITTED", "PENDING");
    assert.strictEqual(match2?.submissionId || null, "sub-pending-002");

    const match3 = studentSubmissionMap.get(asg3);
    assert.strictEqual(match3?.status || "NOT_SUBMITTED", "TAMPERED");
    assert.strictEqual(match3?.submissionId || null, "sub-tampered-003");
  });
});

describe("Assignment Lifecycle & Safe Deletion / Archiving API", () => {
  let server: Server;
  let baseUrl: string;
  const testSecret = "test-jwt-secret-for-assignment-lifecycle";

  const professorId = new mongoose.Types.ObjectId();
  const studentId = new mongoose.Types.ObjectId();
  const targetAssignmentId = new mongoose.Types.ObjectId();

  let professorToken: string;
  let studentToken: string;

  const originalUserFindById = User.findById;
  const originalAssignmentFindById = Assignment.findById;
  const originalAssignmentFindByIdAndDelete = Assignment.findByIdAndDelete;
  const originalSubmissionCountDocuments = Submission.countDocuments;

  let activeAssignmentDoc: any = null;
  let mockSubmissionCount = 0;

  before(() => {
    process.env.JWT_SECRET = testSecret;

    professorToken = jwt.sign(
      { id: professorId.toString(), email: "prof@blocksubmit.edu", role: "professor" },
      testSecret,
      { expiresIn: "1h" }
    );
    studentToken = jwt.sign(
      { id: studentId.toString(), email: "student@blocksubmit.edu", role: "student" },
      testSecret,
      { expiresIn: "1h" }
    );

    User.findById = ((id: any) => {
      const idStr = id ? id.toString() : "";
      if (idStr === professorId.toString()) {
        return Promise.resolve({
          _id: professorId,
          role: "professor",
          email: "prof@blocksubmit.edu",
          name: "Dr. Ananya Rao",
          initials: "AR",
        });
      }
      if (idStr === studentId.toString()) {
        return Promise.resolve({
          _id: studentId,
          role: "student",
          email: "student@blocksubmit.edu",
          name: "Aarav Menon",
          initials: "AM",
        });
      }
      return Promise.resolve(null);
    }) as any;

    Assignment.findById = ((id: any) => {
      if (id && id.toString() === targetAssignmentId.toString()) {
        return Promise.resolve(activeAssignmentDoc);
      }
      return Promise.resolve(null);
    }) as any;

    Submission.countDocuments = (() => {
      return Promise.resolve(mockSubmissionCount);
    }) as any;

    Assignment.findByIdAndDelete = ((id: any) => {
      return Promise.resolve(activeAssignmentDoc);
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
    Assignment.findById = originalAssignmentFindById;
    Assignment.findByIdAndDelete = originalAssignmentFindByIdAndDelete;
    Submission.countDocuments = originalSubmissionCountDocuments;

    return new Promise((resolve) => {
      server.close(() => resolve());
    });
  });

  it("PUT /api/assignments/:id rejects unauthenticated request with 401", async () => {
    const res = await fetch(`${baseUrl}/api/assignments/${targetAssignmentId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "Updated Title" }),
    });
    assert.strictEqual(res.status, 401);
  });

  it("PUT /api/assignments/:id rejects student update with 403 Forbidden", async () => {
    const res = await fetch(`${baseUrl}/api/assignments/${targetAssignmentId}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${studentToken}`,
      },
      body: JSON.stringify({ title: "Student Malicious Update" }),
    });
    assert.strictEqual(res.status, 403);
  });

  it("PUT /api/assignments/:id allows professor to update title, description, and extend deadline", async () => {
    let saved = false;
    const futureDeadline = new Date(Date.now() + 1000 * 60 * 60 * 72);

    activeAssignmentDoc = {
      _id: targetAssignmentId,
      title: "Original Title",
      code: "CS-402",
      description: "Original Description",
      deadline: new Date(Date.now() - 1000 * 60 * 60), // previously expired
      status: "CLOSED",
      submissionCount: 5,
      requirements: ["PDF only"],
      save: async function () {
        saved = true;
        return this;
      },
      toJSON: function () {
        return {
          id: this._id.toString(),
          title: this.title,
          code: this.code,
          description: this.description,
          deadline: this.deadline.toISOString(),
          status: this.status,
          submissionCount: this.submissionCount,
          requirements: this.requirements,
        };
      },
    };

    const res = await fetch(`${baseUrl}/api/assignments/${targetAssignmentId}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${professorToken}`,
      },
      body: JSON.stringify({
        title: "Extended Assignment Title",
        description: "Updated detailed instructions for consensus protocol audit.",
        deadline: futureDeadline.toISOString(),
      }),
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(saved, true);
    assert.strictEqual(body.title, "Extended Assignment Title");
    assert.strictEqual(body.description, "Updated detailed instructions for consensus protocol audit.");
    // Automatically reactivated to ACTIVE because deadline was extended into future
    assert.strictEqual(body.status, "ACTIVE");
  });

  it("DELETE /api/assignments/:id prevents deletion when assignment has submissions (409 Conflict)", async () => {
    mockSubmissionCount = 3; // Assignment HAS submissions
    activeAssignmentDoc = {
      _id: targetAssignmentId,
      title: "Assignment With Submissions",
      submissionCount: 3,
    };

    const res = await fetch(`${baseUrl}/api/assignments/${targetAssignmentId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${professorToken}` },
    });

    assert.strictEqual(res.status, 409);
    const body = await res.json();
    assert.strictEqual(body.hasSubmissions, true);
    assert.match(body.message, /Cannot delete an assignment with existing submissions/i);
    assert.match(body.message, /Archive or close/i);
  });

  it("DELETE /api/assignments/:id allows permanent deletion when assignment has ZERO submissions", async () => {
    mockSubmissionCount = 0; // ZERO submissions
    activeAssignmentDoc = {
      _id: targetAssignmentId,
      title: "Empty Draft Assignment",
      submissionCount: 0,
    };

    const res = await fetch(`${baseUrl}/api/assignments/${targetAssignmentId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${professorToken}` },
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.match(body.message, /deleted successfully/i);
    assert.strictEqual(body.id, targetAssignmentId.toString());
  });

  it("PUT /api/assignments/:id allows professor to safely archive an assignment with submissions", async () => {
    let saved = false;
    activeAssignmentDoc = {
      _id: targetAssignmentId,
      title: "Assignment To Archive",
      code: "CS-402",
      description: "Description",
      deadline: new Date(Date.now() + 1000 * 60 * 60 * 24),
      status: "ACTIVE",
      submissionCount: 12,
      requirements: ["PDF only"],
      save: async function () {
        saved = true;
        return this;
      },
      toJSON: function () {
        return {
          id: this._id.toString(),
          title: this.title,
          code: this.code,
          description: this.description,
          deadline: this.deadline.toISOString(),
          status: this.status,
          submissionCount: this.submissionCount,
          requirements: this.requirements,
        };
      },
    };

    const res = await fetch(`${baseUrl}/api/assignments/${targetAssignmentId}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${professorToken}`,
      },
      body: JSON.stringify({
        status: "ARCHIVED",
      }),
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(saved, true);
    assert.strictEqual(body.status, "ARCHIVED");
    // Submissions and proofs remain completely intact
    assert.strictEqual(body.submissionCount, 12);
  });
});
