import { jsonEncode } from "./encoding.ts";

export function encodeCredential(c) {
	if (c.type !== "public-key") throw new Error("type must be public key");
	const cred = c;
	const { rawId, response: res } = cred;
	if (res instanceof AuthenticatorAssertionResponse) {
		return jsonEncode({
			rawId,
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
			response: {
				clientDataJSON: res.clientDataJSON,
				attestationObject: res.attestationObject,
				// todo transports
			},
		});
	}
	throw new Error("unsupported response");
}
