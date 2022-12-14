import { base64urlEncode, cborDecode } from "./encoding.ts";

// COSE https://www.iana.org/assignments/cose/cose.xhtml

// can uncomment algorithms when a test case exists in verify.test.ts
export const algorithms = new Map([
	// [-8, "EdDSA"],

	[-7, "ES256"],
	// [-35, "ES384"],
	// [-36, "ES512"],

	// [-37, "PS256"],
	// [-38, "PS384"],
	// [-39, "PS512"],

	[-257, "RS256"],
	// [-258, "RS384"],
	// [-259, "RS512"],
]);

const keyTypes = new Map([
	[1, "OKP"],
	[2, "EC"],
	[3, "RSA"],
]);

const curves = new Map([
	[1, "P-256"],
	[2, "P-384"],
	[3, "P-512"],
	[6, "Ed25519"],
]);

function publicJWK(cosePublicKey: Uint8Array): JsonWebKey {
	const key = cborDecode(cosePublicKey);
	const jwk: JsonWebKey = { key_ops: ["verify"], ext: false };
	jwk.alg = algorithms.get(key[3]);
	if (!jwk.alg) throw new Error("unsupported algorithm");
	jwk.kty = keyTypes.get(key[1]);
	if (jwk.kty === "OKP") {
		jwk.crv = curves.get(key[-1]);
		if (jwk.crv !== "Ed25519") throw new Error("bad curve");
		jwk.x = base64urlEncode(key[-2]);
		if (!jwk.x.length) throw new Error("bad x value");
	} else if (jwk.kty === "EC") {
		jwk.crv = curves.get(key[-1]);
		if (!jwk.crv || !jwk.crv.startsWith("P-")) throw new Error("bad curve");
		jwk.x = base64urlEncode(key[-2]);
		if (!jwk.x.length) throw new Error("bad x value");
		jwk.y = base64urlEncode(key[-3]);
		if (!jwk.y.length) throw new Error("bad y value");
	} else if (jwk.kty === "RSA") {
		jwk.n = base64urlEncode(key[-1]);
		if (!jwk.n.length) throw new Error("bad n value");
		jwk.e = base64urlEncode(key[-2]);
		if (!jwk.e.length) throw new Error("bad e value");
	} else {
		throw new Error("unsupported key type");
	}
	return jwk;
}

// https://github.com/webauthn-open-source/fido2-lib/blob/e96e11b503db0ffbd2af075be1e049ad55215952/lib/toolbox.js#L66
function derToRaw(sig: Uint8Array) {
	const rStart = sig[4] === 0 ? 5 : 4;
	const rEnd = rStart + 32;
	const sStart = sig[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
	return new Uint8Array([...sig.slice(rStart, rEnd), ...sig.slice(sStart)]);
}

type VerifyParams = AlgorithmIdentifier | RsaPssParams | EcdsaParams;

function verifyParams({ alg }: JsonWebKey): VerifyParams {
	if (alg === "EdDSA") return { name: "Ed25519" };
	if (alg === "ES256") return { name: "ECDSA", hash: "SHA-256" };
	if (alg === "ES384") return { name: "ECDSA", hash: "SHA-384" };
	if (alg === "ES512") return { name: "ECDSA", hash: "SHA-512" };
	if (alg === "PS256") return { name: "RSA-PSS", saltLength: 32 };
	if (alg === "PS384") return { name: "RSA-PSS", saltLength: 48 };
	if (alg === "PS512") return { name: "RSA-PSS", saltLength: 64 };
	if (alg === "RS256") return { name: "RSASSA-PKCS1-v1_5" };
	if (alg === "RS384") return { name: "RSASSA-PKCS1-v1_5" };
	if (alg === "RS512") return { name: "RSASSA-PKCS1-v1_5" };
	throw new Error("unknown alg for verify");
}

type ImportParams = AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;

function importParams({ alg }: JsonWebKey): ImportParams {
	if (alg === "EdDSA") return { name: "Ed25519", namedCurve: "Ed25519" };
	if (alg === "ES256") return { name: "ECDSA", namedCurve: "P-256" };
	if (alg === "ES384") return { name: "ECDSA", namedCurve: "P-384" };
	if (alg === "ES512") return { name: "ECDSA", namedCurve: "P-512" };
	if (alg === "PS256") return { name: "RSA-PSS", hash: "SHA-256" };
	if (alg === "PS384") return { name: "RSA-PSS", hash: "SHA-384" };
	if (alg === "PS512") return { name: "RSA-PSS", hash: "SHA-512" };
	if (alg === "RS256") return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
	if (alg === "RS384") return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" };
	if (alg === "RS512") return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" };
	throw new Error("unknown alg for import");
}

export async function verifySignature(
	cosePublicKey: Uint8Array,
	data: Uint8Array,
	signature: Uint8Array,
) {
	const jwk = publicJWK(cosePublicKey);
	const sig = jwk.kty === "EC" ? derToRaw(signature) : signature;
	const key = await crypto.subtle.importKey("jwk", jwk, importParams(jwk), false, ["verify"]);
	return await crypto.subtle.verify(verifyParams(jwk), key, sig, data);
}
