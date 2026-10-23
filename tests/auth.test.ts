import { describe, it } from "node:test";
import assert from "node:assert/strict";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { deriveInitials, User } from "../src/models/User";
import { TokenPayload } from "../src/middleware/auth";

describe("User Model & Initials", () => {
  it("derives initials correctly from multi-word names", () => {
    assert.strictEqual(deriveInitials("Dr. Ananya Rao"), "AR");
    assert.strictEqual(deriveInitials("Aarav Menon"), "AM");
    assert.strictEqual(deriveInitials("John Doe"), "JD");
  });

  it("handles single-word names and edge cases", () => {
    assert.strictEqual(deriveInitials("Satoshi"), "SA");
    assert.strictEqual(deriveInitials(""), "U");
  });

  it("hashes password with bcrypt and compares correctly", async () => {
    const rawPassword = "securePassword123";
    const hash = await bcrypt.hash(rawPassword, 10);

    assert.notStrictEqual(hash, rawPassword);
    assert.strictEqual(await bcrypt.compare(rawPassword, hash), true);
    assert.strictEqual(await bcrypt.compare("wrongPassword", hash), false);
  });

  it("ensures User toJSON strips passwordHash and exposes id", () => {
    const mockUser = new User({
      name: "Dr. Ananya Rao",
      email: "professor@blocksubmit.edu",
      passwordHash: "$2b$10$fakehashthatshouldneverleaktoanyclient",
      role: "professor",
      initials: "AR",
      department: "Computer Science",
    });

    const json = mockUser.toJSON();
    assert.strictEqual(typeof json.id, "string");
    assert.strictEqual(json.name, "Dr. Ananya Rao");
    assert.strictEqual(json.email, "professor@blocksubmit.edu");
    assert.strictEqual(json.role, "professor");
    assert.strictEqual(json.initials, "AR");
    assert.strictEqual(json.department, "Computer Science");
    assert.strictEqual((json as Record<string, unknown>).passwordHash, undefined);
    assert.strictEqual((json as Record<string, unknown>)._id, undefined);
    assert.strictEqual((json as Record<string, unknown>).__v, undefined);
  });
});

describe("JWT Authentication & Token Security", () => {
  const testSecret = "test-jwt-secret-key-for-unit-tests-only";

  it("generates and verifies JWT tokens with expected payload", () => {
    const payload: TokenPayload = {
      id: "660000000000000000000001",
      email: "student@blocksubmit.edu",
      role: "student",
    };

    const token = jwt.sign(payload, testSecret, { expiresIn: "1h" });
    assert.strictEqual(typeof token, "string");

    const decoded = jwt.verify(token, testSecret) as TokenPayload;
    assert.strictEqual(decoded.id, payload.id);
    assert.strictEqual(decoded.email, payload.email);
    assert.strictEqual(decoded.role, payload.role);
  });

  it("rejects token with invalid secret", () => {
    const token = jwt.sign({ id: "123" }, testSecret);
    assert.throws(() => {
      jwt.verify(token, "different-wrong-secret");
    });
  });
});

describe("User Provisioning & Update Validation", () => {
  it("validates valid input for new user provisioning", async () => {
    const { validateProvisionInput } = await import("../src/scripts/create-user");
    const result = validateProvisionInput({
      email: "professor@blocksubmit.edu",
      password: "validPassword123",
      name: "Dr. Ananya Rao",
      role: "professor",
    });
    assert.strictEqual(result.valid, true);
  });

  it("requires name when allowUpdate is false", async () => {
    const { validateProvisionInput } = await import("../src/scripts/create-user");
    const result = validateProvisionInput({
      email: "professor@blocksubmit.edu",
      password: "validPassword123",
      allowUpdate: false,
    });
    assert.strictEqual(result.valid, false);
    assert.match(result.error || "", /name must be at least 2 characters/i);
  });

  it("permits omitting name when allowUpdate is true", async () => {
    const { validateProvisionInput } = await import("../src/scripts/create-user");
    const result = validateProvisionInput({
      email: "professor@blocksubmit.edu",
      password: "validPassword123",
      allowUpdate: true,
    });
    assert.strictEqual(result.valid, true);
  });

  it("rejects password shorter than 4 chars or longer than 72 chars", async () => {
    const { validateProvisionInput } = await import("../src/scripts/create-user");
    const shortResult = validateProvisionInput({
      email: "professor@blocksubmit.edu",
      password: "123",
      name: "Professor",
    });
    assert.strictEqual(shortResult.valid, false);

    const longResult = validateProvisionInput({
      email: "professor@blocksubmit.edu",
      password: "a".repeat(73),
      name: "Professor",
    });
    assert.strictEqual(longResult.valid, false);
  });

  it("updates existing user password hash and verifies candidate password", async () => {
    const oldPassword = "oldPassword123";
    const newPassword = "newSecurePassword456";

    const user = new User({
      name: "Test Professor",
      email: "professor@blocksubmit.edu",
      passwordHash: await bcrypt.hash(oldPassword, 10),
      role: "professor",
      initials: "TP",
      department: "Computer Science",
    });

    assert.strictEqual(await user.comparePassword(oldPassword), true);
    assert.strictEqual(await user.comparePassword(newPassword), false);

    // Simulate password update with salt rounds 10
    user.passwordHash = await bcrypt.hash(newPassword, 10);

    assert.strictEqual(await user.comparePassword(newPassword), true);
    assert.strictEqual(await user.comparePassword(oldPassword), false);
  });
});
