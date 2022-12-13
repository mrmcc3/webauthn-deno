import { base64urlEncode, cborDecode, hexEncode } from "./encoding.ts";
import { algorithms } from "./keys.ts";

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

interface VerifyRegArg {
	credential: RegistrationCredential;
	expectedChallenge: Uint8Array;
	allowedOrigins: string[];
	allowedRPs: string[];
}

interface AttestationObject {
	authData: Uint8Array;
	fmt: string;
}

interface VerifyResult {
	sigCount: number;
	credentialId: Uint8Array;
	publicKey: Uint8Array;
	// transports: AuthenticatorTransport[];
}

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

export async function verifyRegistration({
	credential: { rawId, response: { clientDataJSON, attestationObject } },
	expectedChallenge,
	allowedOrigins,
	allowedRPs,
}: VerifyRegArg): Promise<VerifyResult> {
	// steps 1-4 are client side
	const { type, challenge, origin } = JSON.parse(
		new TextDecoder().decode(clientDataJSON),
	) as CollectedClientData; // 5 & 6
	if (type !== "webauthn.create") throw new Error("invalid client data type"); // 7
	if (challenge !== base64urlEncode(expectedChallenge)) {
		throw new Error("challenge mismatch"); // 8
	}
	if (!new Set(allowedOrigins).has(origin)) {
		throw new Error("origin not allowed"); // 9
	}
	// 10. not required for attestation none.
	const { authData, fmt } = cborDecode(new Uint8Array(attestationObject)) as AttestationObject; // 11
	const dv = new DataView(authData.slice().buffer);
	await checkRP(authData.slice(0, 32), allowedRPs); // 12
	const flags = parseFlags(dv.getUint8(32));
	if (!flags.up) throw new Error("user not present"); // 13
	if (!flags.uv) throw new Error("user not verified"); // 14
	const sigCount = dv.getUint32(33);
	// const aaguid = authData.slice(37, 53); not used
	const credentialIdLength = dv.getUint16(53);
	const credentialEnd = 55 + credentialIdLength;
	const credentialId = authData.slice(55, credentialEnd);
	if (hexEncode(credentialId) !== hexEncode(rawId)) {
		throw new Error("credential id mismatch");
	}
	const publicKey = authData.slice(credentialEnd);
	if (!algorithms.has(cborDecode(publicKey)[3])) {
		throw new Error("unsupported algorithm"); // 15
	}
	// 16. no extensions
	if (fmt !== "none") throw new Error("attestation is not supported"); // 17 - 20
	if (credentialIdLength > 1023) throw new Error("credential id is too long"); // 21
	// remaining steps to be performed by caller
	return {
		sigCount,
		credentialId: rawId,
		publicKey,
		// transports
	};
}
