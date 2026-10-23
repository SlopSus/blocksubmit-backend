import mongoose, { Document, Schema } from "mongoose";

export type AssignmentStatus = "ACTIVE" | "CLOSED" | "DRAFT";

export interface IAssignment extends Document {
  id: string;
  title: string;
  code: string;
  description: string;
  deadline: Date;
  status: AssignmentStatus;
  submissionCount: number;
  requirements: string[];
  createdBy: mongoose.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

export function generateAssignmentCode(): string {
  const prefix = "CS";
  const num = Math.floor(100 + Math.random() * 900);
  return `${prefix}-${num}`;
}

const assignmentSchema = new Schema<IAssignment>(
  {
    title: {
      type: String,
      required: [true, "Title is required"],
      trim: true,
      minlength: [3, "Title must be at least 3 characters"],
      maxlength: [150, "Title must not exceed 150 characters"],
    },
    code: {
      type: String,
      required: [true, "Coursework code is required"],
      trim: true,
      uppercase: true,
      maxlength: [20, "Course code must not exceed 20 characters"],
    },
    description: {
      type: String,
      required: [true, "Description is required"],
      trim: true,
      minlength: [5, "Description must be at least 5 characters"],
      maxlength: [5000, "Description must not exceed 5000 characters"],
    },
    deadline: {
      type: Date,
      required: [true, "Deadline is required"],
    },
    status: {
      type: String,
      enum: {
        values: ["ACTIVE", "CLOSED", "DRAFT"],
        message: "Status must be ACTIVE, CLOSED, or DRAFT",
      },
      default: "ACTIVE",
    },
    submissionCount: {
      type: Number,
      default: 0,
      min: 0,
    },
    requirements: {
      type: [String],
      default: ["PDF format only", "Maximum file size: 10 MB"],
    },
    createdBy: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
  },
  {
    timestamps: true,
    toJSON: {
      transform(_doc, ret: Record<string, unknown>) {
        return {
          id: (ret._id as mongoose.Types.ObjectId).toString(),
          title: ret.title,
          code: ret.code,
          description: ret.description,
          deadline: ret.deadline ? new Date(ret.deadline as string | number | Date).toISOString() : null,
          status: ret.status,
          submissionCount: ret.submissionCount ?? 0,
          requirements: ret.requirements ?? [],
          createdAt: ret.createdAt ? new Date(ret.createdAt as string | number | Date).toISOString() : null,
        };
      },
    },
  }
);

assignmentSchema.index({ createdAt: -1 });
assignmentSchema.index({ code: 1 });

export const Assignment = mongoose.model<IAssignment>("Assignment", assignmentSchema);
