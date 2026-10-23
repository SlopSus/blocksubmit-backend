import { Contract, JsonRpcProvider, Wallet } from "ethers";
import { BLOCKSUBMIT_ABI } from "../config/contract";

export interface BlockchainRecordResult {
  transactionHash: string;
  blockNumber: number;
  timestamp: string;
  status: "CONFIRMED" | "FAILED";
}

export interface IBlockchainService {
  recordSubmission(submissionId: string, documentHash: string): Promise<BlockchainRecordResult>;
  verifyHash(submissionId: string, documentHash: string): Promise<boolean>;
  getSubmission(submissionId: string): Promise<unknown>;
}

export class BlockchainService implements IBlockchainService {
  private provider: JsonRpcProvider;
  private wallet: Wallet;
  private contract: Contract;
  private readContract: Contract;

  constructor(rpcUrl?: string, contractAddress?: string, privateKey?: string) {
    const url = rpcUrl || process.env.BLOCKCHAIN_RPC_URL || "http://127.0.0.1:8545";
    const address = contractAddress || process.env.CONTRACT_ADDRESS;
    const key = privateKey || process.env.SIGNER_PRIVATE_KEY;

    if (!address) {
      throw new Error("CONTRACT_ADDRESS environment variable is not defined");
    }
    if (!key) {
      throw new Error("SIGNER_PRIVATE_KEY environment variable is not defined");
    }

    this.provider = new JsonRpcProvider(url);
    this.wallet = new Wallet(key, this.provider);
    this.contract = new Contract(address, BLOCKSUBMIT_ABI, this.wallet);
    this.readContract = new Contract(address, BLOCKSUBMIT_ABI, this.provider);
  }

  async recordSubmission(
    submissionId: string,
    documentHash: string
  ): Promise<BlockchainRecordResult> {
    const tx = await this.contract.recordSubmission(submissionId, documentHash);
    const receipt = await tx.wait(1);

    if (!receipt || receipt.status !== 1) {
      throw new Error("Transaction execution failed or reverted on chain");
    }

    let timestamp = new Date().toISOString();
    try {
      const block = await this.provider.getBlock(receipt.blockNumber);
      if (block) {
        timestamp = new Date(block.timestamp * 1000).toISOString();
      }
    } catch {
      // Fallback to system timestamp if block lookup is delayed
    }

    return {
      transactionHash: receipt.hash,
      blockNumber: receipt.blockNumber,
      timestamp,
      status: "CONFIRMED",
    };
  }

  async verifyHash(submissionId: string, documentHash: string): Promise<boolean> {
    try {
      const result = await this.readContract.verifyHash(submissionId, documentHash);
      return Boolean(result);
    } catch {
      // Contract reverts with "Submission not found" if submissionId is unrecorded
      return false;
    }
  }

  async getSubmission(submissionId: string): Promise<unknown> {
    return await this.readContract.getSubmission(submissionId);
  }
}

let activeBlockchainService: IBlockchainService | null = null;

export function getBlockchainService(): IBlockchainService {
  if (!activeBlockchainService) {
    activeBlockchainService = new BlockchainService();
  }
  return activeBlockchainService;
}

export function setBlockchainService(service: IBlockchainService | null): void {
  activeBlockchainService = service;
}
