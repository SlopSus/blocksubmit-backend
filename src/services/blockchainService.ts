import { Contract, JsonRpcProvider, Wallet } from "ethers";
import { BLOCKSUBMIT_ABI } from "../config/contract";

export class BlockchainInfrastructureError extends Error {
  constructor(message: string, public readonly originalError?: unknown) {
    super(message);
    this.name = "BlockchainInfrastructureError";
  }
}

export class BlockchainRecordNotFoundError extends Error {
  constructor(message: string = "Submission not found on blockchain") {
    super(message);
    this.name = "BlockchainRecordNotFoundError";
  }
}

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
  private contractAddress: string;

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

    this.contractAddress = address;
    this.provider = new JsonRpcProvider(url);
    this.wallet = new Wallet(key, this.provider);
    this.contract = new Contract(address, BLOCKSUBMIT_ABI, this.wallet);
    this.readContract = new Contract(address, BLOCKSUBMIT_ABI, this.provider);
  }

  async recordSubmission(
    submissionId: string,
    documentHash: string
  ): Promise<BlockchainRecordResult> {
    // 1. Verify RPC provider connectivity and contract deployment before sending transaction
    let code: string;
    try {
      code = await this.provider.getCode(this.contractAddress);
    } catch (netErr) {
      throw new BlockchainInfrastructureError(
        `Failed to query blockchain RPC: ${netErr instanceof Error ? netErr.message : String(netErr)}`,
        netErr
      );
    }

    if (!code || code === "0x") {
      throw new BlockchainInfrastructureError(
        `Smart contract is not deployed at address ${this.contractAddress} on the connected blockchain network`
      );
    }

    // 2. Submit transaction to smart contract
    let tx;
    try {
      tx = await this.contract.recordSubmission(submissionId, documentHash);
    } catch (txErr) {
      const msg = txErr instanceof Error ? txErr.message : String(txErr);
      throw new BlockchainInfrastructureError(`Failed to send blockchain transaction: ${msg}`, txErr);
    }

    let receipt;
    try {
      receipt = await tx.wait(1);
    } catch (waitErr) {
      const msg = waitErr instanceof Error ? waitErr.message : String(waitErr);
      throw new BlockchainInfrastructureError(`Failed waiting for transaction receipt: ${msg}`, waitErr);
    }

    if (!receipt || receipt.status !== 1) {
      throw new BlockchainInfrastructureError("Transaction execution failed or reverted on chain");
    }

    // 3. Confirm expected contract event exists in receipt logs
    let hasExpectedEvent = false;
    if (Array.isArray(receipt.logs) && receipt.logs.length > 0) {
      for (const log of receipt.logs) {
        try {
          const parsed = this.contract.interface.parseLog({
            topics: [...log.topics],
            data: log.data,
          });
          if (parsed && parsed.name === "SubmissionRecorded") {
            if (!documentHash || parsed.args.documentHash === documentHash) {
              hasExpectedEvent = true;
              break;
            }
          }
        } catch {
          // Log is not from this contract or does not match event signature
        }
      }
    }

    if (!hasExpectedEvent) {
      throw new BlockchainInfrastructureError(
        `Transaction succeeded on chain (tx: ${receipt.hash}) but contract event 'SubmissionRecorded' was not emitted. Possible call to uninitialized address or contract mismatch.`
      );
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
    // 1. Verify RPC provider connectivity and contract deployment
    let code: string;
    try {
      code = await this.provider.getCode(this.contractAddress);
    } catch (netErr) {
      throw new BlockchainInfrastructureError(
        `Failed to query blockchain RPC: ${netErr instanceof Error ? netErr.message : String(netErr)}`,
        netErr
      );
    }

    if (!code || code === "0x") {
      throw new BlockchainInfrastructureError(
        `Smart contract is not deployed at address ${this.contractAddress} on the connected blockchain network`
      );
    }

    // 2. Call verifyHash on the smart contract
    try {
      const result = await this.readContract.verifyHash(submissionId, documentHash);
      return Boolean(result);
    } catch (callErr) {
      const message = callErr instanceof Error ? callErr.message : String(callErr);

      if (message.includes("Submission not found")) {
        throw new BlockchainRecordNotFoundError(
          `Submission '${submissionId}' was not found on the blockchain contract`
        );
      }

      if (message.includes("could not decode result data") || (callErr as any)?.code === "BAD_DATA") {
        throw new BlockchainInfrastructureError(
          `Blockchain RPC returned invalid data or contract interface mismatch: ${message}`,
          callErr
        );
      }

      if ((callErr as any)?.code === "CALL_EXCEPTION" || message.includes("execution reverted")) {
        throw new BlockchainRecordNotFoundError(
          `Blockchain call reverted: ${message}`
        );
      }

      throw new BlockchainInfrastructureError(
        `Blockchain RPC communication error: ${message}`,
        callErr
      );
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
