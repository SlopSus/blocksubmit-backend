import { describe, it, before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { Server } from "http";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import { app } from "../src/app";
import { User } from "../src/models/User";
import { Submission } from "../src/models/Submission";
import { requireRole } from "../src/middleware/auth";
import {
  IBlockchainService,
  BlockchainRecordResult,
  setBlockchainService,
} from "../src/services/blockchainService";

describe("PDF Magic Byte Validation & Hashing", () => {
  it("detects valid PDF magic bytes (%PDF-)", () => {
    const validPdfBuffer = Buffer.from("%PDF-1.4 sample pdf content for testing");
    const isMagicValid =
      validPdfBuffer.length >= 4 && validPdfBuffer.toString("utf8", 0, 4) === "%PDF";
    assert.strictEqual(isMagicValid, true);
  });

  it("rejects non-PDF files missing magic bytes", () => {
    const textBuffer = Buffer.from("Just plain text, not a PDF document");
    const isMagicValid =
      textBuffer.length >= 4 && textBuffer.toString("utf8", 0, 4) === "%PDF";
    assert.strictEqual(isMagicValid, false);

    const pngBuffer = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const isPngValid = pngBuffer.length >= 4 && pngBuffer.toString("utf8", 0, 4) === "%PDF";
    assert.strictEqual(isPngValid, false);
  });

  it("computes accurate SHA-256 fingerprint from bytes", () => {
    const fileBytes = Buffer.from("%PDF-1.5 test content for academic integrity");
    const hash = crypto.createHash("sha256").update(fileBytes).digest("hex");

    assert.strictEqual(typeof hash, "string");
    assert.strictEqual(hash.length, 64);
    assert.match(hash, /^[a-f0-9]{64}$/);

    // Identical bytes produce identical hash
    const hashCopy = crypto.createHash("sha256").update(fileBytes).digest("hex");
    assert.strictEqual(hash, hashCopy);

    // Tampered byte produces completely different hash
    const tamperedBytes = Buffer.from("%PDF-1.5 test content for academic integrity [MODIFIED]");
    const tamperedHash = crypto.createHash("sha256").update(tamperedBytes).digest("hex");
    assert.notStrictEqual(hash, tamperedHash);
  });
});

describe("Submission Model Transformation", () => {
  it("formats Submission toJSON according to frontend domain requirements", () => {
    const mockStudentRef = new mongoose.Types.ObjectId();
    const mockAssignmentRef = new mongoose.Types.ObjectId();
    const submissionId = "sub-test-123456789";

    const mockSubmission = new Submission({
      submissionId,
      student: {
        id: mockStudentRef.toString(),
        name: "Aarav Menon",
        email: "student@blocksubmit.edu",
        initials: "AM",
      },
      studentRef: mockStudentRef,
      assignmentId: mockAssignmentRef.toString(),
      assignmentRef: mockAssignmentRef,
      assignmentTitle: "Distributed Systems Research Paper",
      documentName: "distributed_consensus.pdf",
      storagePath: "/safe/uploads/sub-test-123456789.pdf",
      fileSize: 2450000,
      submittedAt: new Date("2026-10-23T20:00:00.000Z"),
      status: "PENDING",
      trustedHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      currentHash: null,
      hashMatch: null,
      proof: {
        transactionHash: "0x15027027a24f23b8729bf0a194b28c2bb510a2afcdd3df83747cab7b2e3bf5fd",
        blockNumber: 42,
        timestamp: "2026-10-23T20:01:00.000Z",
        status: "CONFIRMED",
      },
    });

    const json = mockSubmission.toJSON();
    assert.strictEqual(json.id, submissionId);
    assert.strictEqual(json.assignmentTitle, "Distributed Systems Research Paper");
    assert.strictEqual(json.documentName, "distributed_consensus.pdf");
    assert.strictEqual(json.fileSize, 2450000);
    assert.strictEqual(json.status, "PENDING");
    assert.strictEqual(
      json.trustedHash,
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert.strictEqual(json.currentHash, null);
    assert.strictEqual(json.hashMatch, null);
    assert.strictEqual(json.proof?.status, "CONFIRMED");
    assert.strictEqual(json.proof?.blockNumber, 42);

    // Verify storage path and internal database references are hidden
    assert.strictEqual((json as Record<string, unknown>).storagePath, undefined);
    assert.strictEqual((json as Record<string, unknown>).studentRef, undefined);
    assert.strictEqual((json as Record<string, unknown>).assignmentRef, undefined);
    assert.strictEqual((json as Record<string, unknown>)._id, undefined);
    assert.strictEqual((json as Record<string, unknown>).__v, undefined);
  });
});

describe("Blockchain Service Failure & Mock Behavior", () => {
  it("rejects confirmation if blockchain transaction reverts or throws", async () => {
    // Mock failing blockchain service
    const mockFailingService: IBlockchainService = {
      recordSubmission: async () => {
        throw new Error("RPC Error: execution reverted: Submission already exists");
      },
      verifyHash: async () => false,
      getSubmission: async () => null,
    };

    let caughtError: Error | null = null;
    try {
      await mockFailingService.recordSubmission("sub-dup", "hash");
    } catch (err) {
      caughtError = err as Error;
    }

    assert.notStrictEqual(caughtError, null);
    assert.match(caughtError!.message, /execution reverted/i);
  });

  it("returns CONFIRMED status only when receipt status is successful", async () => {
    const mockSuccessService: IBlockchainService = {
      recordSubmission: async (submissionId: string) => {
        return {
          transactionHash: "0xabc123mocktxhash",
          blockNumber: 101,
          timestamp: new Date().toISOString(),
          status: "CONFIRMED",
        };
      },
      verifyHash: async (_id: string, hash: string) => hash === "matching-hash",
      getSubmission: async () => null,
    };

    const res: BlockchainRecordResult = await mockSuccessService.recordSubmission(
      "sub-test",
      "matching-hash"
    );
    assert.strictEqual(res.status, "CONFIRMED");
    assert.strictEqual(res.blockNumber, 101);
    assert.strictEqual(res.transactionHash, "0xabc123mocktxhash");

    // Positive verifyHash
    assert.strictEqual(await mockSuccessService.verifyHash("sub-test", "matching-hash"), true);
    // Tampered verifyHash
    assert.strictEqual(await mockSuccessService.verifyHash("sub-test", "mismatched-hash"), false);
  });
});

describe("Role Guards for Submissions & Verifications", () => {
  it("prevents professors from executing student submission endpoint", () => {
    let statusCode = 0;
    const req = { user: { role: "professor" } } as any;
    const res = {
      status: (code: number) => {
        statusCode = code;
        return { json: () => {} };
      },
    } as any;

    requireRole("student")(req, res, () => {});
    assert.strictEqual(statusCode, 403);
  });

  it("prevents students from executing professor verification endpoint", () => {
    let statusCode = 0;
    const req = { user: { role: "student" } } as any;
    const res = {
      status: (code: number) => {
        statusCode = code;
        return { json: () => {} };
      },
    } as any;

    requireRole("professor")(req, res, () => {});
    assert.strictEqual(statusCode, 403);
  });
});

describe("GET /api/submissions/:id/document - Secure PDF Retrieval", () => {
  let server: Server;
  let baseUrl: string;
  const testSecret = "test-jwt-secret-for-routes-must-be-long-enough";
  const studentAId = new mongoose.Types.ObjectId();
  const studentBId = new mongoose.Types.ObjectId();
  const professorId = new mongoose.Types.ObjectId();

  let studentAToken: string;
  let studentBToken: string;
  let professorToken: string;

  const testUploadDir = path.resolve(process.cwd(), "uploads");
  const testFileId = "sub-test-document-unit";
  const testFilePath = path.join(testUploadDir, `${testFileId}.pdf`);
  const dummyPdfContent = "%PDF-1.4 Unit Test PDF Document Content Bytes";

  let mockSubmissionDoc: any = null;
  const originalFindOne = Submission.findOne;
  const originalUserFindById = User.findById;

  before(() => {
    process.env.JWT_SECRET = testSecret;

    studentAToken = jwt.sign(
      { id: studentAId.toString(), email: "studentA@blocksubmit.edu", role: "student" },
      testSecret,
      { expiresIn: "1h" }
    );
    studentBToken = jwt.sign(
      { id: studentBId.toString(), email: "studentB@blocksubmit.edu", role: "student" },
      testSecret,
      { expiresIn: "1h" }
    );
    professorToken = jwt.sign(
      { id: professorId.toString(), email: "prof@blocksubmit.edu", role: "professor" },
      testSecret,
      { expiresIn: "1h" }
    );

    if (!fs.existsSync(testUploadDir)) {
      fs.mkdirSync(testUploadDir, { recursive: true });
    }
    fs.writeFileSync(testFilePath, dummyPdfContent);

    // Mock User.findById for authenticateJWT middleware
    User.findById = ((id: any) => {
      const idStr = id ? id.toString() : "";
      if (idStr === studentAId.toString()) {
        return Promise.resolve({
          _id: studentAId,
          role: "student",
          email: "studentA@blocksubmit.edu",
          name: "Student A",
          initials: "SA",
        });
      }
      if (idStr === studentBId.toString()) {
        return Promise.resolve({
          _id: studentBId,
          role: "student",
          email: "studentB@blocksubmit.edu",
          name: "Student B",
          initials: "SB",
        });
      }
      if (idStr === professorId.toString()) {
        return Promise.resolve({
          _id: professorId,
          role: "professor",
          email: "prof@blocksubmit.edu",
          name: "Test Professor",
          initials: "TP",
        });
      }
      return Promise.resolve(null);
    }) as any;

    // Mock Submission.findOne to return mockSubmissionDoc
    Submission.findOne = ((query: any) => {
      return {
        select: (fields: string) => Promise.resolve(mockSubmissionDoc),
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
    Submission.findOne = originalFindOne;
    User.findById = originalUserFindById;
    if (fs.existsSync(testFilePath)) {
      fs.unlinkSync(testFilePath);
    }
    return new Promise((resolve) => {
      server.close(() => resolve());
    });
  });

  it("rejects unauthenticated document requests with 401", async () => {
    const res = await fetch(`${baseUrl}/api/submissions/${testFileId}/document`);
    assert.strictEqual(res.status, 401);
  });

  it("returns 404 if submission is not found", async () => {
    mockSubmissionDoc = null;
    const res = await fetch(`${baseUrl}/api/submissions/nonexistent/document`, {
      headers: { Authorization: `Bearer ${professorToken}` },
    });
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(body.message, /submission not found/i);
  });

  it("returns 404 if stored file does not exist on disk", async () => {
    mockSubmissionDoc = {
      submissionId: testFileId,
      studentRef: studentAId,
      documentName: "missing.pdf",
      storagePath: path.join("uploads", "ghost-file-does-not-exist.pdf"),
    };

    const res = await fetch(`${baseUrl}/api/submissions/${testFileId}/document`, {
      headers: { Authorization: `Bearer ${professorToken}` },
    });
    assert.strictEqual(res.status, 404);
    const body = await res.json();
    assert.match(body.message, /stored document file not found/i);
  });

  it("rejects a student attempting to retrieve another student's document with 403", async () => {
    mockSubmissionDoc = {
      submissionId: testFileId,
      studentRef: studentAId,
      documentName: "student_a_paper.pdf",
      storagePath: path.join("uploads", `${testFileId}.pdf`),
    };

    const res = await fetch(`${baseUrl}/api/submissions/${testFileId}/document`, {
      headers: { Authorization: `Bearer ${studentBToken}` }, // Student B attempting to access Student A's doc
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.match(body.message, /forbidden/i);
  });

  it("allows student to retrieve their own document with valid headers and content", async () => {
    mockSubmissionDoc = {
      submissionId: testFileId,
      studentRef: studentAId,
      documentName: "student_a_paper.pdf",
      storagePath: path.join("uploads", `${testFileId}.pdf`),
    };

    const res = await fetch(`${baseUrl}/api/submissions/${testFileId}/document`, {
      headers: { Authorization: `Bearer ${studentAToken}` },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get("content-type"), "application/pdf");
    assert.strictEqual(res.headers.get("x-content-type-options"), "nosniff");
    assert.match(res.headers.get("content-disposition") || "", /inline; filename="student_a_paper\.pdf"/);

    const text = await res.text();
    assert.strictEqual(text, dummyPdfContent);
  });

  it("allows professor to retrieve any student's document with valid headers and content", async () => {
    mockSubmissionDoc = {
      submissionId: testFileId,
      studentRef: studentAId,
      documentName: "student_a_paper.pdf",
      storagePath: path.join("uploads", `${testFileId}.pdf`),
    };

    const res = await fetch(`${baseUrl}/api/submissions/${testFileId}/document`, {
      headers: { Authorization: `Bearer ${professorToken}` },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get("content-type"), "application/pdf");
    assert.strictEqual(res.headers.get("x-content-type-options"), "nosniff");

    const text = await res.text();
    assert.strictEqual(text, dummyPdfContent);
  });

  it("rejects path traversal attempts with 403", async () => {
    mockSubmissionDoc = {
      submissionId: testFileId,
      studentRef: studentAId,
      documentName: "evil.pdf",
      storagePath: path.join("..", "..", "windows", "system32", "calc.exe"),
    };

    const res = await fetch(`${baseUrl}/api/submissions/${testFileId}/document`, {
      headers: { Authorization: `Bearer ${professorToken}` },
    });
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.match(body.message, /forbidden: invalid file path/i);
  });
});

describe("POST /api/submissions/:id/verify - Tamper Detection & Integrity Verification", () => {
  let server: Server;
  let baseUrl: string;
  const testSecret = "test-jwt-secret-for-routes-must-be-long-enough";
  const professorId = new mongoose.Types.ObjectId();
  let professorToken: string;

  const testUploadDir = path.resolve(process.cwd(), "uploads");
  const tempFilesToClean = new Set<string>();

  let activeMockSubmission: any = null;
  const originalFindOne = Submission.findOne;
  const originalUserFindById = User.findById;

  before(() => {
    process.env.JWT_SECRET = testSecret;

    professorToken = jwt.sign(
      { id: professorId.toString(), email: "prof@blocksubmit.edu", role: "professor" },
      testSecret,
      { expiresIn: "1h" }
    );

    if (!fs.existsSync(testUploadDir)) {
      fs.mkdirSync(testUploadDir, { recursive: true });
    }

    // Mock User.findById for authenticateJWT middleware
    User.findById = ((id: any) => {
      const idStr = id ? id.toString() : "";
      if (idStr === professorId.toString()) {
        return Promise.resolve({
          _id: professorId,
          role: "professor",
          email: "prof@blocksubmit.edu",
          name: "Test Professor",
          initials: "TP",
        });
      }
      return Promise.resolve(null);
    }) as any;

    // Mock Submission.findOne to return activeMockSubmission
    Submission.findOne = ((query: any) => {
      let docToReturn = activeMockSubmission;
      if (activeMockSubmission && query) {
        if (query.submissionId && query.submissionId !== activeMockSubmission.submissionId) {
          docToReturn = null;
        }
      }
      return {
        select: () => Promise.resolve(docToReturn),
        then: (resolve: any, reject: any) => Promise.resolve(docToReturn).then(resolve, reject),
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

  afterEach(() => {
    for (const filePath of tempFilesToClean) {
      try {
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      } catch {
        // Ignore cleanup errors during afterEach
      }
    }
    tempFilesToClean.clear();
    setBlockchainService(null);
    activeMockSubmission = null;
  });

  after(() => {
    Submission.findOne = originalFindOne;
    User.findById = originalUserFindById;
    setBlockchainService(null);

    for (const filePath of tempFilesToClean) {
      try {
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      } catch {
        // Ignore cleanup errors during after
      }
    }
    tempFilesToClean.clear();

    return new Promise((resolve) => {
      server.close(() => resolve());
    });
  });

  it("verifies an authentic temporary PDF: returns 200, status VERIFIED, and hashMatch true", async () => {
    const authenticSubmissionId = "sub-test-authentic-verify-isolated";
    const tempPdfPath = path.join(testUploadDir, `${authenticSubmissionId}.pdf`);
    tempFilesToClean.add(tempPdfPath);

    const originalPdfBytes = Buffer.from("%PDF-1.4 Authentic Academic Paper - Original Bytes");
    const originalHash = crypto.createHash("sha256").update(originalPdfBytes).digest("hex");

    fs.writeFileSync(tempPdfPath, originalPdfBytes);

    const mockDoc = new Submission({
      submissionId: authenticSubmissionId,
      student: {
        id: new mongoose.Types.ObjectId().toString(),
        name: "Test Student",
        email: "student@blocksubmit.edu",
        initials: "TS",
      },
      studentRef: new mongoose.Types.ObjectId(),
      assignmentId: new mongoose.Types.ObjectId().toString(),
      assignmentRef: new mongoose.Types.ObjectId(),
      assignmentTitle: "Authentic Verification Test Assignment",
      documentName: "authentic_paper.pdf",
      storagePath: tempPdfPath,
      fileSize: originalPdfBytes.length,
      submittedAt: new Date("2026-10-23T20:00:00.000Z"),
      status: "PENDING",
      trustedHash: originalHash,
      currentHash: null,
      hashMatch: null,
      proof: {
        transactionHash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        blockNumber: 42,
        timestamp: "2026-10-23T20:01:00.000Z",
        status: "CONFIRMED",
      },
    });

    mockDoc.save = async function () {
      return this;
    };
    activeMockSubmission = mockDoc;

    const mockBlockchainService: IBlockchainService = {
      recordSubmission: async () => ({
        transactionHash: "0x1234567890abcdef",
        blockNumber: 42,
        timestamp: new Date().toISOString(),
        status: "CONFIRMED",
      }),
      verifyHash: async (_subId: string, candidateHash: string) => {
        return candidateHash === originalHash;
      },
      getSubmission: async () => null,
    };
    setBlockchainService(mockBlockchainService);

    const res = await fetch(`${baseUrl}/api/submissions/${authenticSubmissionId}/verify`, {
      method: "POST",
      headers: { Authorization: `Bearer ${professorToken}` },
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();

    assert.strictEqual(body.id, authenticSubmissionId);
    assert.strictEqual(body.status, "VERIFIED");
    assert.strictEqual(body.hashMatch, true);
    assert.strictEqual(body.trustedHash, originalHash);
    assert.strictEqual(body.currentHash, originalHash);

    // Verify mock document in-memory state was updated
    assert.strictEqual(mockDoc.status, "VERIFIED");
    assert.strictEqual(mockDoc.hashMatch, true);
    assert.strictEqual(mockDoc.currentHash, originalHash);
  });

  it("detects document tampering: untouched PDF is VERIFIED, then modified PDF becomes TAMPERED with hashMatch false", async () => {
    const tamperSubmissionId = "sub-test-tamper-detection-isolated";
    const tempPdfPath = path.join(testUploadDir, `${tamperSubmissionId}.pdf`);
    tempFilesToClean.add(tempPdfPath);

    const originalPdfBytes = Buffer.from(
      "%PDF-1.4 Authentic Academic Paper - Original Bytes Before Tampering"
    );
    const originalTrustedHash = crypto.createHash("sha256").update(originalPdfBytes).digest("hex");

    fs.writeFileSync(tempPdfPath, originalPdfBytes);

    const mockDoc = new Submission({
      submissionId: tamperSubmissionId,
      student: {
        id: new mongoose.Types.ObjectId().toString(),
        name: "Test Student",
        email: "student@blocksubmit.edu",
        initials: "TS",
      },
      studentRef: new mongoose.Types.ObjectId(),
      assignmentId: new mongoose.Types.ObjectId().toString(),
      assignmentRef: new mongoose.Types.ObjectId(),
      assignmentTitle: "Tamper Detection Test Assignment",
      documentName: "tamper_test_paper.pdf",
      storagePath: tempPdfPath,
      fileSize: originalPdfBytes.length,
      submittedAt: new Date("2026-10-23T20:00:00.000Z"),
      status: "PENDING",
      trustedHash: originalTrustedHash,
      currentHash: null,
      hashMatch: null,
      proof: {
        transactionHash: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        blockNumber: 43,
        timestamp: "2026-10-23T20:01:00.000Z",
        status: "CONFIRMED",
      },
    });

    mockDoc.save = async function () {
      return this;
    };
    activeMockSubmission = mockDoc;

    // Mock blockchain anchors ONLY the original trusted hash
    const mockBlockchainService: IBlockchainService = {
      recordSubmission: async () => ({
        transactionHash: "0xabcdef1234567890",
        blockNumber: 43,
        timestamp: new Date().toISOString(),
        status: "CONFIRMED",
      }),
      verifyHash: async (_subId: string, candidateHash: string) => {
        return candidateHash === originalTrustedHash;
      },
      getSubmission: async () => null,
    };
    setBlockchainService(mockBlockchainService);

    // Step 1: Verify untouched PDF first -> assert VERIFIED and hashMatch true
    const resInitial = await fetch(`${baseUrl}/api/submissions/${tamperSubmissionId}/verify`, {
      method: "POST",
      headers: { Authorization: `Bearer ${professorToken}` },
    });

    assert.strictEqual(resInitial.status, 200);
    const bodyInitial = await resInitial.json();
    assert.strictEqual(bodyInitial.status, "VERIFIED");
    assert.strictEqual(bodyInitial.hashMatch, true);
    assert.strictEqual(bodyInitial.trustedHash, originalTrustedHash);
    assert.strictEqual(bodyInitial.currentHash, originalTrustedHash);

    // Step 2: Modify the temporary file bytes without changing trustedHash or mocked original blockchain anchor
    const tamperedPdfBytes = Buffer.from(
      "%PDF-1.4 Tampered Document - Attacker Injected Different Bytes"
    );
    const expectedTamperedHash = crypto.createHash("sha256").update(tamperedPdfBytes).digest("hex");
    assert.notStrictEqual(expectedTamperedHash, originalTrustedHash);

    fs.writeFileSync(tempPdfPath, tamperedPdfBytes);

    // Step 3: Verify again -> assert status TAMPERED, hashMatch false, and currentHash differs from trustedHash
    const resTampered = await fetch(`${baseUrl}/api/submissions/${tamperSubmissionId}/verify`, {
      method: "POST",
      headers: { Authorization: `Bearer ${professorToken}` },
    });

    assert.strictEqual(resTampered.status, 200);
    const bodyTampered = await resTampered.json();

    assert.strictEqual(bodyTampered.id, tamperSubmissionId);
    assert.strictEqual(bodyTampered.status, "TAMPERED");
    assert.strictEqual(bodyTampered.hashMatch, false);
    assert.strictEqual(bodyTampered.trustedHash, originalTrustedHash);
    assert.strictEqual(bodyTampered.currentHash, expectedTamperedHash);
    assert.notStrictEqual(bodyTampered.currentHash, bodyTampered.trustedHash);

    // Verify mock document in-memory state updated to TAMPERED
    assert.strictEqual(mockDoc.status, "TAMPERED");
    assert.strictEqual(mockDoc.hashMatch, false);
    assert.strictEqual(mockDoc.currentHash, expectedTamperedHash);
  });
});
