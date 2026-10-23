import { Router, Request, Response, NextFunction } from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import multer from "multer";
import mongoose from "mongoose";
import { Submission, ISubmission } from "../models/Submission";
import { Assignment } from "../models/Assignment";
import { authenticateJWT, requireRole } from "../middleware/auth";
import { getBlockchainService } from "../services/blockchainService";

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

      // Check assignment deadline
      if (new Date(assignment.deadline).getTime() <= Date.now()) {
        res.status(400).json({ message: "Assignment deadline has passed. Submissions are closed." });
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

      const storagePath = path.join(uploadDir, `${submissionId}.pdf`);
      fs.writeFileSync(storagePath, file.buffer);

      // Record on smart contract
      const blockchainService = getBlockchainService();
      let proofResult;

      try {
        proofResult = await blockchainService.recordSubmission(submissionId, documentHash);
      } catch (chainError) {
        // Clean up file if blockchain transaction fails
        if (fs.existsSync(storagePath)) {
          fs.unlinkSync(storagePath);
        }
        const msg = chainError instanceof Error ? chainError.message : "Blockchain transaction failed";
        res.status(502).json({
          message: `Failed to record submission proof on blockchain: ${msg}`,
        });
        return;
      }

      if (!proofResult || proofResult.status !== "CONFIRMED") {
        if (fs.existsSync(storagePath)) {
          fs.unlinkSync(storagePath);
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
    } catch (error) {
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

      // Verify on-chain record via contract view function
      const blockchainService = getBlockchainService();
      const isBlockchainMatch = await blockchainService.verifyHash(submission.submissionId, currentHash);

      const isMatch = isBlockchainMatch && currentHash === submission.trustedHash;

      submission.status = isMatch ? "VERIFIED" : "TAMPERED";
      submission.currentHash = currentHash;
      submission.hashMatch = isMatch;

      await submission.save();

      res.status(200).json(submission.toJSON());
    } catch (error) {
      const message = error instanceof Error ? error.message : "Verification failed";
      res.status(500).json({ message });
    }
  }
);
