import mongoose, { Document, Schema } from "mongoose";

export type IntegrityStatus = "PENDING" | "VERIFIED" | "TAMPERED";

export interface IBlockchainProof {
  transactionHash: string | null;
  blockNumber: number | null;
  timestamp: string | null;
  status: "CONFIRMED" | "PENDING" | "FAILED" | null;
}

export interface IStudentSnapshot {
  id: string;
  name: string;
  email: string;
  initials: string;
}

export interface ISubmission extends Document {
  submissionId: string;
  student: IStudentSnapshot;
  studentRef: mongoose.Types.ObjectId;
  assignmentId: string;
  assignmentRef: mongoose.Types.ObjectId;
  assignmentTitle: string;
  documentName: string;
  storagePath: string;
  fileSize: number;
  submittedAt: Date;
  status: IntegrityStatus;
  trustedHash: string | null;
  currentHash: string | null;
  hashMatch: boolean | null;
  proof: IBlockchainProof | null;
  createdAt: Date;
  updatedAt: Date;
}

const proofSchema = new Schema<IBlockchainProof>(
  {
    transactionHash: { type: String, default: null },
    blockNumber: { type: Number, default: null },
    timestamp: { type: String, default: null },
    status: {
      type: String,
      enum: ["CONFIRMED", "PENDING", "FAILED", null],
      default: "PENDING",
    },
  },
  { _id: false }
);

const studentSnapshotSchema = new Schema<IStudentSnapshot>(
  {
    id: { type: String, required: true },
    name: { type: String, required: true },
    email: { type: String, required: true },
    initials: { type: String, required: true },
  },
  { _id: false }
);

const submissionSchema = new Schema<ISubmission>(
  {
    submissionId: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    student: {
      type: studentSnapshotSchema,
      required: true,
    },
    studentRef: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    assignmentId: {
      type: String,
      required: true,
      index: true,
    },
    assignmentRef: {
      type: Schema.Types.ObjectId,
      ref: "Assignment",
      required: true,
      index: true,
    },
    assignmentTitle: {
      type: String,
      required: true,
      trim: true,
    },
    documentName: {
      type: String,
      required: true,
      trim: true,
    },
    storagePath: {
      type: String,
      required: true,
    },
    fileSize: {
      type: Number,
      required: true,
      min: 0,
    },
    submittedAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
    status: {
      type: String,
      enum: ["PENDING", "VERIFIED", "TAMPERED"],
      default: "PENDING",
    },
    trustedHash: {
      type: String,
      default: null,
    },
    currentHash: {
      type: String,
      default: null,
    },
    hashMatch: {
      type: Boolean,
      default: null,
    },
    proof: {
      type: proofSchema,
      default: null,
    },
  },
  {
    timestamps: true,
    toJSON: {
      transform(_doc, ret: Record<string, unknown>) {
        return {
          id: (ret.submissionId as string) || (ret._id as mongoose.Types.ObjectId).toString(),
          student: ret.student,
          assignmentId: ret.assignmentId,
          assignmentTitle: ret.assignmentTitle,
          documentName: ret.documentName,
          fileSize: ret.fileSize,
          submittedAt: ret.submittedAt
            ? new Date(ret.submittedAt as string | number | Date).toISOString()
            : new Date().toISOString(),
          status: ret.status,
          trustedHash: ret.trustedHash ?? null,
          currentHash: ret.currentHash ?? null,
          hashMatch: ret.hashMatch ?? null,
          proof: ret.proof ?? null,
        };
      },
    },
  }
);

submissionSchema.index({ submissionId: 1 }, { unique: true });
submissionSchema.index(
  { studentRef: 1, assignmentId: 1 },
  {
    unique: true,
    partialFilterExpression: {
      studentRef: { $exists: true },
      assignmentId: { $exists: true, $type: "string" },
    },
  }
);
submissionSchema.index(
  { studentRef: 1, assignmentRef: 1 },
  {
    unique: true,
    partialFilterExpression: {
      studentRef: { $exists: true },
      assignmentRef: { $exists: true, $type: "objectId" },
    },
  }
);

export const Submission = mongoose.model<ISubmission>("Submission", submissionSchema);
