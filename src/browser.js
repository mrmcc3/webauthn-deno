import { jsonEncode } from "./encoding.ts";

export { jsonDecode as decodeOptions } from "./encoding.ts";

export function encodeCredential(c) {
	if (c.type !== "public-key") throw new Error("type must be public key");
	const cred = c;
	const { rawId, response: res, authenticatorAttachment } = cred;
	if (res instanceof AuthenticatorAssertionResponse) {
		return jsonEncode({
			rawId,
			authenticatorAttachment,
			response: {
				clientDataJSON: res.clientDataJSON,
				authenticatorData: res.authenticatorData,
				signature: res.signature,
				userHandle: res.userHandle,
			},
		});
	} else if (res instanceof AuthenticatorAttestationResponse) {
		return jsonEncode({
			rawId,
			authenticatorAttachment,
			response: {
				clientDataJSON: res.clientDataJSON,
				attestationObject: res.attestationObject,
				// TODO transports
			},
		});
	}
	throw new Error("unsupported response");
}

export async function isUVPA() {
	if (
		typeof document !== "undefined" &&
		typeof window.PublicKeyCredential !== "undefined" &&
		typeof window.PublicKeyCredential
				.isUserVerifyingPlatformAuthenticatorAvailable === "function"
	) {
		return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
	}
	return false;
}

export async function isCMA() {
	if (
		typeof document !== "undefined" &&
		typeof window.PublicKeyCredential !== "undefined" &&
		typeof window.PublicKeyCredential.isConditionalMediationAvailable ===
			"function"
	) {
		return await PublicKeyCredential.isConditionalMediationAvailable();
	}
	return false;
}
