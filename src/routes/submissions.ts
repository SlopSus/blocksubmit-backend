import { Router, Request, Response, NextFunction } from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import multer from "multer";
import mongoose from "mongoose";
import { Submission, ISubmission } from "../models/Submission";
import { Assignment } from "../models/Assignment";
import { authenticateJWT, requireRole } from "../middleware/auth";
import {
  getBlockchainService,
  BlockchainInfrastructureError,
  BlockchainRecordNotFoundError,
} from "../services/blockchainService";

export const submissionRouter = Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10 MB maximum
  },
  fileFilter: (_req, file, cb) => {
    const isPdfMime = file.mimetype === "application/pdf";
    const isPdfExt = file.originalname.toLowerCase().endsWith(".pdf");

    if (!isPdfMime && !isPdfExt) {
      cb(new Error("Invalid document format. Only PDF files are accepted."));
      return;
    }
    cb(null, true);
  },
});

const uploadMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  upload.single("document")(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === "LIMIT_FILE_SIZE") {
        res.status(400).json({ message: "File exceeds the 10 MB limit." });
        return;
      }
      res.status(400).json({ message: `File upload error: ${err.message}` });
      return;
    } else if (err) {
      res.status(400).json({ message: err.message || "File upload failed." });
      return;
    }
    next();
  });
};

// POST /api/submissions - Student document upload and blockchain recording
submissionRouter.post(
  "/",
  authenticateJWT,
  requireRole("student"),
  uploadMiddleware,
  async (req: Request, res: Response): Promise<void> => {
    let storagePath: string | null = null;
    try {
      const { assignmentId } = req.body;
      const file = req.file;

      if (!assignmentId || typeof assignmentId !== "string") {
        res.status(400).json({ message: "assignmentId is required." });
        return;
      }

      if (!file || !file.buffer) {
        res.status(400).json({ message: "PDF document file is required." });
        return;
      }

      // Magic byte verification: Valid PDF must start with '%PDF-' (0x25, 0x50, 0x44, 0x46)
      if (file.buffer.length < 4 || file.buffer.toString("utf8", 0, 4) !== "%PDF") {
        res.status(400).json({
          message: "Invalid file content. The uploaded file is missing standard PDF magic bytes.",
        });
        return;
      }

      // Validate assignment exists
      if (!mongoose.Types.ObjectId.isValid(assignmentId)) {
        res.status(404).json({ message: "Assignment not found." });
        return;
      }

      const assignment = await Assignment.findById(assignmentId);
      if (!assignment) {
        res.status(404).json({ message: "Assignment not found." });
        return;
      }

      // Check for existing submission by this student for this assignment
      const existingSubmission = await Submission.findOne({
        studentRef: req.user!._id,
        $or: [{ assignmentId: assignment._id.toString() }, { assignmentRef: assignment._id }],
      });

      if (existingSubmission) {
        res.status(409).json({
          message: "You have already submitted a document for this assignment.",
          submissionId: existingSubmission.submissionId,
        });
        return;
      }

      // Check assignment deadline
      if (new Date(assignment.deadline).getTime() <= Date.now()) {
        res.status(400).json({ message: "Assignment deadline has passed. Submissions are closed." });
        return;
      }

      // Check assignment status
      if (assignment.status === "CLOSED" || assignment.status === "ARCHIVED" || assignment.status === "DRAFT") {
        res.status(400).json({ message: `Submissions are closed for this assignment (status: ${assignment.status}).` });
        return;
      }

      // Compute SHA-256 fingerprint from actual file bytes
      const documentHash = crypto.createHash("sha256").update(file.buffer).digest("hex");

      // Generate unique immutable submission ID
      const submissionId = `sub-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

      // Save PDF to isolated storage directory
      const uploadDir = process.env.UPLOAD_DIR || path.join(process.cwd(), "uploads");
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }

      storagePath = path.join(uploadDir, `${submissionId}.pdf`);
      fs.writeFileSync(storagePath, file.buffer);

      // Record on smart contract
      const blockchainService = getBlockchainService();
      let proofResult;

      try {
        proofResult = await blockchainService.recordSubmission(submissionId, documentHash);
      } catch (chainError) {
        // Clean up file if blockchain transaction fails
        if (storagePath && fs.existsSync(storagePath)) {
          fs.unlinkSync(storagePath);
          storagePath = null;
        }
        const msg = chainError instanceof Error ? chainError.message : "Blockchain transaction failed";
        res.status(502).json({
          message: `Failed to record submission proof on blockchain: ${msg}`,
        });
        return;
      }

      if (!proofResult || proofResult.status !== "CONFIRMED") {
        if (storagePath && fs.existsSync(storagePath)) {
          fs.unlinkSync(storagePath);
          storagePath = null;
        }
        res.status(502).json({
          message: "Blockchain transaction did not receive a confirmed receipt.",
        });
        return;
      }

      // Save submission in MongoDB with confirmed proof
      const submission = await Submission.create({
        submissionId,
        student: {
          id: req.user!._id.toString(),
          name: req.user!.name,
          email: req.user!.email,
          initials: req.user!.initials,
        },
        studentRef: req.user!._id,
        assignmentId: assignment._id.toString(),
        assignmentRef: assignment._id,
        assignmentTitle: assignment.title,
        documentName: file.originalname,
        storagePath,
        fileSize: file.size || file.buffer.length,
        submittedAt: new Date(),
        status: "PENDING",
        trustedHash: documentHash,
        currentHash: null,
        hashMatch: null,
        proof: {
          transactionHash: proofResult.transactionHash,
          blockNumber: proofResult.blockNumber,
          timestamp: proofResult.timestamp,
          status: "CONFIRMED",
        },
      });

      // Increment assignment submissionCount
      await Assignment.findByIdAndUpdate(assignment._id, { $inc: { submissionCount: 1 } });

      res.status(201).json(submission.toJSON());
    } catch (error: any) {
      if (storagePath && fs.existsSync(storagePath)) {
        try {
          fs.unlinkSync(storagePath);
        } catch {
          // ignore cleanup errors
        }
      }

      if (error?.code === 11000) {
        res.status(409).json({
          message: "You have already submitted a document for this assignment.",
        });
        return;
      }

      const message = error instanceof Error ? error.message : "Submission processing failed";
      res.status(500).json({ message });
    }
  }
);

// GET /api/submissions - List submissions filtered by role and ownership
submissionRouter.get("/", authenticateJWT, async (req: Request, res: Response): Promise<void> => {
  try {
    const isStudent = req.user?.role === "student";

    const query = isStudent ? { studentRef: req.user!._id } : {};
    const submissions = await Submission.find(query).sort({ submittedAt: -1 });

    res.status(200).json(submissions.map((s) => s.toJSON()));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to retrieve submissions";
    res.status(500).json({ message });
  }
});

// GET /api/submissions/:id - Fetch single submission details
submissionRouter.get("/:id", authenticateJWT, async (req: Request, res: Response): Promise<void> => {
  try {
    const rawId = req.params.id;
    const id = Array.isArray(rawId) ? rawId[0] : String(rawId);

    const query = mongoose.Types.ObjectId.isValid(id)
      ? { $or: [{ _id: id }, { submissionId: id }] }
      : { submissionId: id };

    const submission = await Submission.findOne(query);
    if (!submission) {
      res.status(404).json({ message: "Submission not found." });
      return;
    }

    // Role ownership check: Students may only view their own submissions
    if (req.user?.role === "student" && submission.studentRef.toString() !== req.user._id.toString()) {
      res.status(403).json({ message: "Forbidden: You cannot access another student's submission." });
      return;
    }

    res.status(200).json(submission.toJSON());
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to retrieve submission";
    res.status(500).json({ message });
  }
});

// GET /api/submissions/:id/document - Securely stream original PDF document bytes
submissionRouter.get("/:id/document", authenticateJWT, async (req: Request, res: Response): Promise<void> => {
  try {
    const rawId = req.params.id;
    const id = Array.isArray(rawId) ? rawId[0] : String(rawId);

    const query = mongoose.Types.ObjectId.isValid(id)
      ? { $or: [{ _id: id }, { submissionId: id }] }
      : { submissionId: id };

    const submission = await Submission.findOne(query).select("+storagePath");
    if (!submission) {
      res.status(404).json({ message: "Submission not found." });
      return;
    }

    // Role ownership check: Students may only access their own submissions
    if (req.user?.role === "student" && submission.studentRef.toString() !== req.user._id.toString()) {
      res.status(403).json({ message: "Forbidden: You cannot access another student's submission." });
      return;
    }

    const uploadDir = path.resolve(process.env.UPLOAD_DIR || path.join(process.cwd(), "uploads")).toLowerCase();
    const resolvedPath = path.resolve(process.cwd(), submission.storagePath);

    // Path traversal check
    if (!resolvedPath.toLowerCase().startsWith(uploadDir)) {
      res.status(403).json({ message: "Forbidden: Invalid file path." });
      return;
    }

    if (!fs.existsSync(resolvedPath)) {
      res.status(404).json({ message: "Stored document file not found on server." });
      return;
    }

    const cleanFilename = path.basename(submission.documentName || "document.pdf").replace(/["\r\n]/g, "");
    const encodedFilename = encodeURIComponent(cleanFilename);

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `inline; filename="${cleanFilename}"; filename*=UTF-8''${encodedFilename}`);
    res.setHeader("X-Content-Type-Options", "nosniff");

    res.sendFile(resolvedPath);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to retrieve document";
    res.status(500).json({ message });
  }
});

// POST /api/submissions/:id/verify - Professor document integrity verification
submissionRouter.post(
  "/:id/verify",
  authenticateJWT,
  requireRole("professor"),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const rawId = req.params.id;
      const id = Array.isArray(rawId) ? rawId[0] : String(rawId);

      const query = mongoose.Types.ObjectId.isValid(id)
        ? { $or: [{ _id: id }, { submissionId: id }] }
        : { submissionId: id };

      const submission = await Submission.findOne(query);
      if (!submission) {
        res.status(404).json({ message: "Submission not found." });
        return;
      }

      // Check original PDF on server disk
      if (!fs.existsSync(submission.storagePath)) {
        res.status(404).json({ message: "Stored document file not found on server." });
        return;
      }

      // Recompute SHA-256 fingerprint from the stored file bytes
      const currentBytes = fs.readFileSync(submission.storagePath);
      const currentHash = crypto.createHash("sha256").update(currentBytes).digest("hex");

      // 1. Calculate document integrity independently:
      // Compare the calculated PDF hash directly with the trusted submission hash.
      const isFileHashMatch = currentHash === submission.trustedHash;

      // Rule: Mark the document TAMPERED only when the calculated PDF hash genuinely differs from trusted hash.
      if (!isFileHashMatch) {
        submission.status = "TAMPERED";
        submission.currentHash = currentHash;
        submission.hashMatch = false;
        await submission.save();

        res.status(200).json(submission.toJSON());
        return;
      }

      // 2. The PDF hash is authentic (matches trustedHash). Verify against the blockchain.
      const blockchainService = getBlockchainService();
      let isBlockchainMatch = false;

      try {
        isBlockchainMatch = await blockchainService.verifyHash(submission.submissionId, currentHash);
      } catch (chainError) {
        if (chainError instanceof BlockchainRecordNotFoundError) {
          // A missing submission on the current chain must not be interpreted as document tampering.
          res.status(404).json({
            message: `Blockchain verification failed: ${chainError.message}`,
            error: "BLOCKCHAIN_RECORD_NOT_FOUND",
          });
          return;
        }

        const msg = chainError instanceof Error ? chainError.message : "Blockchain service error";
        res.status(502).json({
          message: `Blockchain verification service unavailable: ${msg}`,
          error: "BLOCKCHAIN_UNAVAILABLE",
        });
        return;
      }

      // 3. A contract call that explicitly returns false is preserved distinctly from an RPC failure.
      // Not VERIFIED, but not falsely classified as document tampering.
      if (!isBlockchainMatch) {
        res.status(409).json({
          message: "Blockchain verification failed: on-chain record does not match the document hash.",
          error: "BLOCKCHAIN_HASH_MISMATCH",
        });
        return;
      }

      // 4. Document hash matches AND blockchain verification succeeded.
      submission.status = "VERIFIED";
      submission.currentHash = currentHash;
      submission.hashMatch = true;

      await submission.save();

      res.status(200).json(submission.toJSON());
    } catch (error) {
      const message = error instanceof Error ? error.message : "Verification failed";
      res.status(500).json({ message });
    }
  }
);
