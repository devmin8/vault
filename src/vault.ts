#!/usr/bin/env bun

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";
import argon2 from "argon2";

import type { KdfParams, VaultData } from "./types";

/* =========================
   Constants
========================= */

const MAGIC = new TextEncoder().encode("KVLT");
const VERSION = 1;

const DEFAULT_VAULT_DIR = ".vault";
const DEFAULT_STORE_BASENAME = "vault-store.kv";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/* =========================
   Utils
========================= */

function wipe(buf?: Uint8Array): void {
	if (!buf) return;
	buf.fill(0);
}

/** Resolve shell-style paths: `~/`, `~`, `$VAR`, `${VAR}`. */
function expandPath(input: string): string {
	let s = input.trim();
	if (s === "~" || s.startsWith("~/")) {
		s =
			s === "~"
				? os.homedir()
				: path.join(os.homedir(), s.slice(2));
	}
	s = s.replace(
		/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
		(_m, braced: string | undefined, bare: string | undefined) => {
			const name = braced ?? bare;
			if (!name) return "";
			if (name === "HOME" && process.env.HOME === undefined) {
				return os.homedir();
			}
			return process.env[name] ?? "";
		},
	);
	return path.normalize(s);
}

function defaultVaultStorePath(): string {
	return path.join(os.homedir(), DEFAULT_VAULT_DIR, DEFAULT_STORE_BASENAME);
}

/** True if basename has a typical file extension (e.g. `store.kv`, not `dirname`). */
function looksLikeFilePath(expanded: string): boolean {
	const base = path.basename(expanded);
	const i = base.lastIndexOf(".");
	return i > 0 && i < base.length - 1;
}

function stripTrailingSeparators(p: string): string {
	return p.replace(/[/\\]+$/, "");
}

/**
 * Resolve the vault file path from optional user input.
 * - No input: `~/.vault/vault-store.kv`
 * - Existing directory: `<dir>/vault-store.kv`
 * - Trailing separator: `<dir>/vault-store.kv`
 * - Existing file or non-existent path that looks like a file: use as-is
 * - Non-existent path without file extension: `<path>/vault-store.kv`
 */
function resolveVaultStorePath(userInput: string | undefined): string {
	const trimmed = userInput?.trim();
	if (!trimmed) return defaultVaultStorePath();

	const p = expandPath(trimmed);
	if (/[/\\]$/.test(p)) {
		const dir = stripTrailingSeparators(p);
		const base = dir === "" ? path.sep : dir;
		return path.join(base, DEFAULT_STORE_BASENAME);
	}

	try {
		const st = fs.statSync(p);
		if (st.isDirectory()) return path.join(p, DEFAULT_STORE_BASENAME);
		return p;
	} catch {
		if (looksLikeFilePath(p)) return p;
		return path.join(p, DEFAULT_STORE_BASENAME);
	}
}

function buffersEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) {
		if (a[i] !== b[i]) return false;
	}
	return true;
}

/* =========================
   Binary helpers
========================= */

function writeU16(view: DataView, offset: number, value: number): number {
	view.setUint16(offset, value, true);
	return offset + 2;
}

function writeU32(view: DataView, offset: number, value: number): number {
	view.setUint32(offset, value, true);
	return offset + 4;
}

function writeU64(view: DataView, offset: number, value: bigint): number {
	view.setBigUint64(offset, value, true);
	return offset + 8;
}

function readU16(view: DataView, offset: number): number {
	return view.getUint16(offset, true);
}

function readU32(view: DataView, offset: number): number {
	return view.getUint32(offset, true);
}

function readU64(view: DataView, offset: number): bigint {
	return view.getBigUint64(offset, true);
}

/* =========================
   KDF params (binary)
========================= */

function serializeKdf(kdf: KdfParams): Uint8Array {
	const salt = Buffer.from(kdf.salt, "base64");
	const buf = new Uint8Array(16 + 4 + 4 + 4);
	const view = new DataView(buf.buffer);

	let offset = 0;
	buf.set(salt, offset);
	offset += 16;
	offset = writeU32(view, offset, kdf.memory);
	offset = writeU32(view, offset, kdf.iterations);
	writeU32(view, offset, kdf.parallelism);

	return buf;
}

function deserializeKdf(buf: Uint8Array): KdfParams {
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

	let offset = 0;
	const salt = buf.slice(offset, offset + 16);
	offset += 16;

	const memory = readU32(view, offset);
	offset += 4;
	const iterations = readU32(view, offset);
	offset += 4;
	const parallelism = readU32(view, offset);

	return {
		salt: Buffer.from(salt).toString("base64"),
		memory,
		iterations,
		parallelism,
	};
}

/* =========================
   Vault payload (binary KV)
========================= */

function serializeVaultData(data: VaultData): Uint8Array {
	const entries = Object.entries(data.entries);

	let size = 4;
	for (const [k, v] of entries) {
		size += 2 + encoder.encode(k).length;
		size += 4 + encoder.encode(v).length;
	}
	size += 8;

	const buf = new Uint8Array(size);
	const view = new DataView(buf.buffer);

	let offset = 0;
	offset = writeU32(view, offset, entries.length);

	for (const [key, value] of entries) {
		const keyBytes = encoder.encode(key);
		const valueBytes = encoder.encode(value);

		offset = writeU16(view, offset, keyBytes.length);
		buf.set(keyBytes, offset);
		offset += keyBytes.length;

		offset = writeU32(view, offset, valueBytes.length);
		buf.set(valueBytes, offset);
		offset += valueBytes.length;
	}

	writeU64(view, offset, BigInt(new Date(data.updatedAt).getTime()));
	return buf;
}

function deserializeVaultData(buf: Uint8Array): VaultData {
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

	let offset = 0;

	// Read entry count
	const count = readU32(view, offset);
	offset += 4;

	const entries: Record<string, string> = {};

	// Read each entry
	for (let i = 0; i < count; i++) {
		// key_len (u16) + key_bytes
		const keyLen = readU16(view, offset);
		offset += 2;
		if (offset + keyLen > buf.length) throw new Error("Corrupt vault");

		const keyBytes = decoder.decode(buf.slice(offset, offset + keyLen));
		offset += keyLen;

		const valLen = readU32(view, offset);
		offset += 4;
		if (offset + valLen > buf.length) throw new Error("Corrupt vault");

		const value = decoder.decode(buf.slice(offset, offset + valLen));
		offset += valLen;

		entries[keyBytes] = value;
	}

	const ts = readU64(view, offset);
	const updatedAt =
		ts > BigInt(Number.MAX_SAFE_INTEGER)
			? new Date().toISOString()
			: new Date(Number(ts)).toISOString();

	return { version: 1, updatedAt, entries };
}

/* =========================
   Crypto
========================= */

async function deriveKey(
	password: Uint8Array,
	kdf: KdfParams,
): Promise<Uint8Array> {
	const hash = await argon2.hash(Buffer.from(password), {
		type: argon2.argon2id,
		salt: Buffer.from(kdf.salt, "base64"),
		memoryCost: kdf.memory,
		timeCost: kdf.iterations,
		parallelism: kdf.parallelism,
		hashLength: 32,
		raw: true,
	});

	return new Uint8Array(hash);
}

function encrypt(
	data: VaultData,
	key: Uint8Array,
): { nonce: Uint8Array; ciphertext: Uint8Array } {
	const cipher = new XChaCha20Poly1305(key);
	const nonce = crypto.getRandomValues(new Uint8Array(24));
	const plaintext = serializeVaultData(data);
	const ciphertext = cipher.seal(nonce, plaintext);
	wipe(plaintext);
	return { nonce, ciphertext };
}

function decrypt(
	nonce: Uint8Array,
	ciphertext: Uint8Array,
	key: Uint8Array,
): VaultData {
	const cipher = new XChaCha20Poly1305(key);
	const plaintext = cipher.open(nonce, ciphertext);
	if (!plaintext) throw new Error("Invalid password");
	const data = deserializeVaultData(plaintext);
	wipe(plaintext);
	return data;
}

/* =========================
   File I/O (atomic)
========================= */

function writeVault(
	path: string,
	kdf: KdfParams,
	nonce: Uint8Array,
	ciphertext: Uint8Array,
): void {
	const kdfBytes = serializeKdf(kdf);
	const headerSize = 4 + 1 + 1 + kdfBytes.length;
	const buf = new Uint8Array(headerSize + 24 + ciphertext.length);

	let offset = 0;
	buf.set(MAGIC, offset);
	offset += 4;
	buf[offset++] = VERSION;
	buf[offset++] = kdfBytes.length;
	buf.set(kdfBytes, offset);
	offset += kdfBytes.length;
	buf.set(nonce, offset);
	offset += 24;
	buf.set(ciphertext, offset);

	const tmp = `${path}.tmp`;
	fs.writeFileSync(tmp, buf);
	fs.renameSync(tmp, path);
}

function readVault(path: string): {
	kdf: KdfParams;
	nonce: Uint8Array;
	ciphertext: Uint8Array;
} {
	const buf = new Uint8Array(fs.readFileSync(path));
	let offset = 0;

	if (!buf.slice(0, 4).every((b, i) => b === MAGIC[i])) {
		throw new Error("Invalid vault file");
	}
	offset += 4;

	const version = buf[offset++];
	if (version !== VERSION) throw new Error("Unsupported version");

	const kdfLen = buf[offset++];
	if (kdfLen === undefined)
		throw new Error("Invalid vault file: missing KDF length");
	const kdf = deserializeKdf(buf.slice(offset, offset + kdfLen));
	offset += kdfLen;

	const nonce = buf.slice(offset, offset + 24);
	offset += 24;
	const ciphertext = buf.slice(offset);

	return { kdf, nonce, ciphertext };
}

/* =========================
   CLI helpers
========================= */

function prompt(q: string): Promise<string> {
	const rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout,
	});
	return new Promise((r) =>
		rl.question(q, (a) => {
			rl.close();
			r(a.trim());
		}),
	);
}

function promptHidden(q: string): Promise<Uint8Array> {
	return new Promise((resolve) => {
		const stdin = process.stdin;
		process.stdout.write(q);
		stdin.setRawMode(true);
		stdin.resume();

		const buf: number[] = [];
		const handler = (d: Buffer) => {
			const b = d[0];
			if (b === undefined) return;
			if (b === 13) {
				process.stdout.write("\n");
				stdin.setRawMode(false);
				stdin.pause();
				stdin.removeListener("data", handler);
				resolve(new Uint8Array(buf));
				return;
			}
			if (b === 3) process.exit(1);
			buf.push(b);
		};

		stdin.on("data", handler);
	});
}

/* =========================
   Init + Main
========================= */

async function createVault(vaultPath: string): Promise<void> {
	console.log("\n🆕 Creating new vault\n");
	const pw1 = await promptHidden("🔑 Create master password: ");
	const pw2 = await promptHidden("🔑 Confirm master password: ");

	if (!buffersEqual(pw1, pw2)) {
		wipe(pw1);
		wipe(pw2);
		throw new Error("Passwords do not match");
	}
	wipe(pw2);

	const kdf: KdfParams = {
		salt: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString(
			"base64",
		),
		memory: 65536,
		iterations: 3,
		parallelism: 2,
	};

	const key = await deriveKey(pw1, kdf);
	wipe(pw1);

	const data: VaultData = {
		version: 1,
		updatedAt: new Date().toISOString(),
		entries: {},
	};
	const enc = encrypt(data, key);
	wipe(key);

	const dir = path.dirname(vaultPath);
	fs.mkdirSync(dir, { recursive: true });
	writeVault(vaultPath, kdf, enc.nonce, enc.ciphertext);
	console.log("✅ Vault created");
}

async function main() {
	console.log("\n🔐 Secure KV Vault\n");

	const vaultPath = resolveVaultStorePath(process.argv[2]);
	console.log(`📄 Using vault: ${vaultPath}\n`);

	if (!fs.existsSync(vaultPath)) {
		const create = (await prompt("Vault not found. Create new? (y/N): "))
			.toLowerCase()
			.startsWith("y");
		if (!create) return;
		await createVault(vaultPath);
	}

	const vault = readVault(vaultPath);
	const password = await promptHidden("🔑 Master password: ");
	let key: Uint8Array | undefined;

	try {
		key = await deriveKey(password, vault.kdf);
		const data = decrypt(vault.nonce, vault.ciphertext, key);

		while (true) {
			console.log("\n1) Add  2) Get  3) Delete  4) List  5) Exit");
			const choice = await prompt("> ");

			if (choice === "1") {
				const k = await prompt("Key: ");
				const vBuf = await promptHidden("Value: ");
				data.entries[k] = decoder.decode(vBuf);
				wipe(vBuf);
				console.log("✅ Saved");
			} else if (choice === "2") {
				const k = await prompt("Key: ");
				console.log(data.entries[k] ?? "❌ Not found");
			} else if (choice === "3") {
				const k = await prompt("Key: ");
				delete data.entries[k];
				console.log("🗑️ Deleted");
			} else if (choice === "4") {
				const entries = Object.entries(data.entries);
				if (entries.length === 0) {
					console.log("\n📭 No entries found");
				} else {
					console.log("\n📋 Vault Entries:\n");

					// Calculate column widths
					const maxKeyLen = Math.max(...entries.map(([k]) => k.length), 3);
					const maxValLen = Math.max(...entries.map(([, v]) => v.length), 5);

					// Print header
					const keyHeader = "Key".padEnd(maxKeyLen);
					const valHeader = "Value".padEnd(maxValLen);
					console.log(`│ ${keyHeader} │ ${valHeader} │`);
					console.log(`├${"─".repeat(maxKeyLen + 2)}┼${"─".repeat(maxValLen + 2)}┤`);

					// Print entries
					entries.forEach(([key, value]) => {
						const keyCol = key.padEnd(maxKeyLen);
						const valCol = value.padEnd(maxValLen);
						console.log(`│ ${keyCol} │ ${valCol} │`);
					});
				}
			} else if (choice === "5") {
				data.updatedAt = new Date().toISOString();
				const encrypted = encrypt(data, key);
				writeVault(vaultPath, vault.kdf, encrypted.nonce, encrypted.ciphertext);
				console.log("💾 Vault saved & locked");
				break;
			}
		}
	} catch (e) {
		console.error("❌ Decryption failed");
		if (e instanceof Error && e.message) {
			console.error(e.message);
		}
	} finally {
		wipe(password);
		wipe(key);
	}
}

main();
