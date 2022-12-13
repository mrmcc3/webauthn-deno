import { assertEquals } from "std/testing/asserts.ts";
import { base64urlEncode, hexDecode, jsonDecode } from "./encoding.ts";
import { RegistrationCredential, verifyRegistration } from "./registration.ts";

const case1 = {
	expectedChallenge: "abababababababababababababababab",
	allowedOrigins: ["http://localhost:8000"],
	allowedRPs: ["localhost"],
	creationOpts:
		`{"rp":{"id":"localhost","name":"LocalHost!"},"user":{"id":["~b","q6urqw"],"name":"jdoe","displayName":"John Doe"},"challenge":["~b","q6urq6urq6urq6urq6urqw"],"pubKeyCredParams":[{"alg":-8,"type":"public-key"},{"alg":-7,"type":"public-key"},{"alg":-35,"type":"public-key"},{"alg":-36,"type":"public-key"},{"alg":-37,"type":"public-key"},{"alg":-38,"type":"public-key"},{"alg":-39,"type":"public-key"},{"alg":-257,"type":"public-key"},{"alg":-258,"type":"public-key"},{"alg":-259,"type":"public-key"}],"timeout":300000,"excludeCredentials":[],"authenticatorSelection":{"authenticatorAttachment":"platform","residentKey":"required","userVerification":"required","requireResidentKey":true},"attestation":"none"}`,
	creationResp:
		`{"rawId":["~b","bdYW5bSpRL92idIHIyewXCfcppkuCjFlSV_MOcuPEVY"],"response":{"clientDataJSON":["~b","eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoicTZ1cnE2dXJxNnVycTZ1cnE2dXJxdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9"],"attestationObject":["~b","o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAIG3WFuW0qUS_donSByMnsFwn3KaZLgoxZUlfzDnLjxFWpQECAyYgASFYIOU38k8Zx53ZyeOLOaLTc7hyxh1rCtT5E4CmAras7FWXIlggBYs50cSstWOkgb8MHBVpu5z-SCXAQRmc4V8r4jo4CUI"]}}`,
	credentialId: "bdYW5bSpRL92idIHIyewXCfcppkuCjFlSV_MOcuPEVY",
	publicKey: "pQECAyYgASFYIOU38k8Zx53ZyeOLOaLTc7hyxh1rCtT5E4CmAras7FWXIlggBYs50cSstWOkgb8MHBVpu5z-SCXAQRmc4V8r4jo4CUI",
};

Deno.test({
	name: "test registration",
	async fn() {
		const { creationResp, credentialId, publicKey, expectedChallenge, allowedOrigins, allowedRPs } = case1;
		const res = await verifyRegistration({
			credential: jsonDecode(creationResp) as RegistrationCredential,
			expectedChallenge: hexDecode(expectedChallenge),
			allowedOrigins,
			allowedRPs,
		});
		assertEquals(res.sigCount, 0);
		assertEquals(base64urlEncode(res.credentialId), credentialId);
		assertEquals(base64urlEncode(res.publicKey), publicKey);
	},
});
