import { base64urlEncode, cborDecode, hexEncode } from "./encoding.ts";
import { algorithms, verifySignature } from "./keys.ts";

// --- helpers ---

async function checkRP(rpIdHash: Uint8Array, allowed: string[]) {
	const hashHex = hexEncode(rpIdHash);
	for (const id of allowed) {
		const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(id));
		if (hashHex === hexEncode(hash)) return true;
	}
	throw new Error("relying party not allowed");
}

function parseFlags(flags: number) {
	return {
		up: Boolean(flags & 0b00000001),
		uv: Boolean(flags & 0b00000100),
		at: Boolean(flags & 0b01000000),
	};
}

function concatBuffers(b1: ArrayBuffer, b2: ArrayBuffer) {
	const res = new Uint8Array(b1.byteLength + b2.byteLength);
	res.set(new Uint8Array(b1), 0);
	res.set(new Uint8Array(b2), b1.byteLength);
	return res;
}

// --- Registration (credential attestation) ---

interface AuthenticatorAttestationResponse {
	clientDataJSON: Uint8Array;
	attestationObject: Uint8Array;
}

export interface RegistrationCredential {
	type: "public-key";
	rawId: Uint8Array;
	response: AuthenticatorAttestationResponse;
}

interface CollectedClientData {
	type: string;
	challenge: string;
	origin: string;
	crossOrigin?: boolean;
}

interface AttestationObject {
	authData: Uint8Array;
	fmt: string;
}

interface VerifyRegArg {
	credential: RegistrationCredential;
	expectedChallenge: Uint8Array;
	allowedOrigins: string[];
	allowedRPs: string[];
}

interface VerifyRegResult {
	sigCount: number;
	credId: Uint8Array;
	pubKey: Uint8Array;
	// TODO transports: AuthenticatorTransport[];
}

// follows https://w3c.github.io/webauthn/#sctn-registering-a-new-credential

export async function verifyRegistration({
	credential: { rawId, response: { clientDataJSON, attestationObject } },
	expectedChallenge,
	allowedOrigins,
	allowedRPs,
}: VerifyRegArg): Promise<VerifyRegResult> {
	// steps 1-4 are client side

	// 5-6. extract collected client data
	const { type, challenge, origin } = JSON.parse(
		new TextDecoder().decode(clientDataJSON),
	) as CollectedClientData;

	// 7-9. validate client data
	if (type !== "webauthn.create") {
		throw new Error("invalid client data type"); // 7
	}
	if (challenge !== base64urlEncode(expectedChallenge)) {
		throw new Error("challenge mismatch"); // 8
	}
	if (!new Set(allowedOrigins).has(origin)) {
		throw new Error("origin not allowed"); // 9
	}
	// 10. not required for attestation none.

	// 11. decode attestation object
	const { authData, fmt } = cborDecode(new Uint8Array(attestationObject)) as AttestationObject;

	// 12-14. check authenticator data
	const dv = new DataView(authData.slice().buffer);
	await checkRP(authData.slice(0, 32), allowedRPs); // 12
	const flags = parseFlags(dv.getUint8(32));
	if (!flags.up) throw new Error("user not present"); // 13
	if (!flags.uv) throw new Error("user not verified"); // 14
	// 15-16. not supported

	// extract credId and pubKey
	const sigCount = dv.getUint32(33);
	const credIdLength = dv.getUint16(53);
	const credEnd = 55 + credIdLength;
	const credId = authData.slice(55, credEnd);
	if (hexEncode(credId) !== hexEncode(rawId)) throw new Error("credential id mismatch");
	const pubKey = authData.slice(credEnd);

	// 17. check supported algorithm
	if (!algorithms.has(cborDecode(pubKey)[3])) {
		throw new Error("unsupported algorithm"); // 15
	}

	// 18. no extensions

	// 19-22. attestation
	if (fmt !== "none") throw new Error("attestation is not supported");

	// 23.
	if (credIdLength > 1023) throw new Error("credential id is too long");

	// remaining steps to be performed by caller
	return {
		sigCount,
		credId: rawId,
		pubKey,
		// TODO transports
	};
}

// --- Authentication (credential assertion) ---

interface AuthenticatorAssertionResponse {
	clientDataJSON: Uint8Array;
	authenticatorData: Uint8Array;
	signature: Uint8Array;
	userHandle: Uint8Array;
}

export interface AuthenticationCredential {
	type: "public-key";
	rawId: Uint8Array;
	response: AuthenticatorAssertionResponse;
}

interface StoredCredential {
	userId: Uint8Array;
	pubKey: Uint8Array;
	sigCount: number;
}

interface VerifyAuthArg {
	credential: AuthenticationCredential;
	expectedChallenge: Uint8Array;
	allowedOrigins: string[];
	allowedRPs: string[];
	storedCredential: StoredCredential;
}

interface VerifyAuthResult {
	sigCount: number;
}

// follows https://w3c.github.io/webauthn/#sctn-verifying-assertion

export async function verifyAuthentication({
	credential: { response: { clientDataJSON, authenticatorData, signature, userHandle } },
	expectedChallenge,
	allowedRPs,
	allowedOrigins,
	storedCredential: { userId, pubKey, sigCount: storedSigCount },
}: VerifyAuthArg): Promise<VerifyAuthResult> {
	// 1-4 are client side. 5. not supported

	// 6. check user handle
	if (!userHandle) throw new Error("userHandle is not present");
	if (hexEncode(userHandle) !== hexEncode(userId)) {
		throw new Error("userHandle is not associated with credential");
	}

	// 7-9. extract collected client data
	const { type, challenge, origin } = JSON.parse(
		new TextDecoder().decode(clientDataJSON),
	) as CollectedClientData;

	// 10-12. validate client data
	if (type !== "webauthn.get") {
		throw new Error("invalid client data type"); // 10
	}
	if (challenge !== base64urlEncode(expectedChallenge)) {
		throw new Error("challenge mismatch"); // 11
	}
	if (!new Set(allowedOrigins).has(origin)) {
		throw new Error("origin not allowed"); // 12
	}

	// 13-15. check authenticator data
	await checkRP(authenticatorData.slice(0, 32), allowedRPs); // 13
	const dv = new DataView(authenticatorData.buffer);
	const flags = parseFlags(dv.getUint8(32));
	if (!flags.up) throw new Error("user not present"); // 14
	if (!flags.uv) throw new Error("user not verified"); // 15

	// 16-17. not supported

	// 18. construct data to sign
	const hash = await crypto.subtle.digest("SHA-256", clientDataJSON);
	const data = concatBuffers(authenticatorData, hash);

	// 19. check the signatures match. (18 not required)
	const verified = await verifySignature(pubKey, data, signature);
	if (!verified) throw new Error("signature verification failed");

	// 20. check the signature counter
	const sigCount = dv.getUint32(33); // 20
	if (sigCount > 0 || storedSigCount > 0) {
		if (sigCount <= storedSigCount) throw new Error("signature counter error");
	}

	// 21. not supported
	return { sigCount }; // 22
}
