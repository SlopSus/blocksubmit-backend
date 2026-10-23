export const BLOCKSUBMIT_ABI = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "string",
        name: "submissionId",
        type: "string",
      },
      {
        indexed: false,
        internalType: "string",
        name: "documentHash",
        type: "string",
      },
      {
        indexed: true,
        internalType: "address",
        name: "submittedBy",
        type: "address",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "timestamp",
        type: "uint256",
      },
    ],
    name: "SubmissionRecorded",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "string",
        name: "_submissionId",
        type: "string",
      },
    ],
    name: "getSubmission",
    outputs: [
      {
        internalType: "string",
        name: "submissionId",
        type: "string",
      },
      {
        internalType: "string",
        name: "documentHash",
        type: "string",
      },
      {
        internalType: "address",
        name: "submittedBy",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "timestamp",
        type: "uint256",
      },
      {
        internalType: "bool",
        name: "exists",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "string",
        name: "_submissionId",
        type: "string",
      },
      {
        internalType: "string",
        name: "_documentHash",
        type: "string",
      },
    ],
    name: "recordSubmission",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "string",
        name: "_submissionId",
        type: "string",
      },
      {
        internalType: "string",
        name: "_documentHash",
        type: "string",
      },
    ],
    name: "verifyHash",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;
