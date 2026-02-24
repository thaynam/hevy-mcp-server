import { describe, it, expect } from 'vitest';
import { env } from 'cloudflare:test';
import {
  encryptApiKey,
  decryptApiKey,
  getUserApiKey,
  setUserApiKey,
} from '../../src/lib/key-storage.js';

// Valid AES-256 key: 64 hex chars = 32 bytes
const VALID_KEY_HEX = 'a'.repeat(64);

describe('STEST-01: Encryption round-trip characterization tests', () => {
  // Characterization test: documents CURRENT behavior as of Phase 1.
  // These tests pin existing functionality to prevent regressions during refactoring.

  it('encryptApiKey then decryptApiKey returns the exact original string', async () => {
    const original = 'hv_live_abc123def456';
    const encrypted = await encryptApiKey(original, VALID_KEY_HEX);
    const decrypted = await decryptApiKey(encrypted, VALID_KEY_HEX);
    expect(decrypted).toBe(original);
  });

  it('encrypting the same value twice produces different ciphertexts (random IV), both decrypt to original', async () => {
    const original = 'hv_live_abc123def456';
    const encrypted1 = await encryptApiKey(original, VALID_KEY_HEX);
    const encrypted2 = await encryptApiKey(original, VALID_KEY_HEX);
    expect(encrypted1).not.toBe(encrypted2);
    expect(await decryptApiKey(encrypted1, VALID_KEY_HEX)).toBe(original);
    expect(await decryptApiKey(encrypted2, VALID_KEY_HEX)).toBe(original);
  });

  it('setUserApiKey then getUserApiKey round-trip through KV returns the exact original value', async () => {
    const username = 'testuser-roundtrip';
    const original = 'hv_live_abc123def456';
    await setUserApiKey(env.OAUTH_KV, VALID_KEY_HEX, username, original);
    const result = await getUserApiKey(env.OAUTH_KV, VALID_KEY_HEX, username);
    expect(result).toBe(original);
  });

  it('empty string encrypts and decrypts correctly', async () => {
    // Note: isValidLength requires length > 0, so empty string will throw
    // This documents the contract: empty strings are rejected by encryptApiKey
    await expect(encryptApiKey('', VALID_KEY_HEX)).rejects.toThrow('Invalid API key length');
  });

  it('long string (500 chars) encrypts and decrypts correctly', async () => {
    const original = 'x'.repeat(500);
    const encrypted = await encryptApiKey(original, VALID_KEY_HEX);
    const decrypted = await decryptApiKey(encrypted, VALID_KEY_HEX);
    expect(decrypted).toBe(original);
  });
});

describe('STEST-02: Decryption failure paths - getUserApiKey returns null without throwing', () => {
  // Characterization test: documents CURRENT behavior as of Phase 1.
  // These tests pin existing functionality to prevent regressions during refactoring.

  it('getUserApiKey returns null when decryption fails due to wrong key', async () => {
    const username = 'testuser-wrongkey';
    const original = 'hv_live_abc123def456';
    // Store with the valid key
    await setUserApiKey(env.OAUTH_KV, VALID_KEY_HEX, username, original);
    // Retrieve with a different key
    const wrongKey = 'b'.repeat(64);
    const result = await getUserApiKey(env.OAUTH_KV, wrongKey, username);
    expect(result).toBeNull();
  });

  it('getUserApiKey returns null when KV contains corrupted (non-base64) data', async () => {
    const username = 'corrupteduser';
    await env.OAUTH_KV.put(`hevy_key:${username}`, 'not-valid-base64!!!');
    const result = await getUserApiKey(env.OAUTH_KV, VALID_KEY_HEX, username);
    expect(result).toBeNull();
  });

  it('getUserApiKey returns null when IV is truncated (< 12 bytes)', async () => {
    const username = 'truncateduser';
    // btoa("AAAA") = 4 bytes, too short for IV (12 bytes) + ciphertext
    await env.OAUTH_KV.put(`hevy_key:${username}`, btoa('AAAA'));
    const result = await getUserApiKey(env.OAUTH_KV, VALID_KEY_HEX, username);
    expect(result).toBeNull();
  });

  it('getUserApiKey returns null when KV entry does not exist (key never stored)', async () => {
    const result = await getUserApiKey(env.OAUTH_KV, VALID_KEY_HEX, 'nonexistent-user-xyz');
    expect(result).toBeNull();
  });

  it('decryptApiKey itself throws on invalid hex key format; getUserApiKey catches and returns null', async () => {
    // First encrypt something valid so we have a real ciphertext to test with
    const enc = await encryptApiKey('hv_live_test', VALID_KEY_HEX);
    // decryptApiKey throws for invalid hex key — documents the contract
    await expect(decryptApiKey(enc, 'not-hex')).rejects.toThrow('Invalid encryption key');

    // getUserApiKey catches the throw and returns null
    const username = 'testuser-invalidkey';
    await env.OAUTH_KV.put(`hevy_key:${username}`, enc);
    const result = await getUserApiKey(env.OAUTH_KV, 'not-hex', username);
    expect(result).toBeNull();
  });
});
