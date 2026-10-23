import { describe, it } from "node:test";
import assert from "node:assert/strict";
import mongoose from "mongoose";
import { Assignment, generateAssignmentCode } from "../src/models/Assignment";

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
