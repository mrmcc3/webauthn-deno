import { assertEquals } from "std/testing/asserts.ts";
import { hexDecode, hexEncode, jsonDecode } from "./encoding.ts";
import {
	AuthenticationCredential,
	RegistrationCredential,
	verifyAuthentication,
	verifyRegistration,
} from "./verify.ts";

const ES256 = {
	challenge: "abababababababababababababababab",
	allowedOrigins: ["http://localhost:8000"],
	allowedRPs: ["localhost"],
	user: { id: "abababab", name: "case1", displayName: "Case 1" },
	pubKeyCredParams: [{ type: "public-key", alg: -7 }],
	encodedRegOpts:
		`{"rp":{"id":"localhost","name":"LocalHost!"},"user":{"id":["~b","q6urqw"],"name":"case1","displayName":"Case 1"},"challenge":["~b","q6urq6urq6urq6urq6urqw"],"pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":300000,"excludeCredentials":[],"authenticatorSelection":{"authenticatorAttachment":"platform","residentKey":"required","userVerification":"required","requireResidentKey":true},"attestation":"none"}`,
	encodedRegCred:
		`{"rawId":["~b","shIaRNpGuNM0BoH55SB2mr1SQxfttSnjxVRRVNgufXc"],"response":{"clientDataJSON":["~b","eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoicTZ1cnE2dXJxNnVycTZ1cnE2dXJxdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"],"attestationObject":["~b","o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAILISGkTaRrjTNAaB-eUgdpq9UkMX7bUp48VUUVTYLn13pQECAyYgASFYIMYgVZSLVApLJVhP5gUUnrh1lBPMGb7lpi37iQx16mn7IlggOROohidXDm1xzHYgqRzcIno6PztoqglEIbyC6TvClnA"]}}`,
	credId: "shIaRNpGuNM0BoH55SB2mr1SQxfttSnjxVRRVNgufXc",
	encodedAuthOpts:
		`{"challenge":["~b","q6urq6urq6urq6urq6urqw"],"timeout":300000,"allowCredentials":[{"type":"public-key","id":["~b","shIaRNpGuNM0BoH55SB2mr1SQxfttSnjxVRRVNgufXc"]}],"userVerification":"required","attestation":"none"}`,
	encodedAuthCred:
		`{"rawId":["~b","shIaRNpGuNM0BoH55SB2mr1SQxfttSnjxVRRVNgufXc"],"response":{"clientDataJSON":["~b","eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicTZ1cnE2dXJxNnVycTZ1cnE2dXJxdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"],"authenticatorData":["~b","SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ"],"signature":["~b","MEYCIQCEFRUHNql0i44X4yOyKwyjT4RCscmrTsDDEHnnKerPXAIhAI6qS1eTeid0JB7ly8HaibDRd9ngZyDoq1hz2XFL5j6Y"],"userHandle":["~b","q6urqw"]}}`,
};

const RS256 = {
	challenge: "01010101010101010101010101010101",
	allowedOrigins: ["http://localhost:8000"],
	allowedRPs: ["localhost"],
	user: { id: "01010101", name: "case2", displayName: "Case 2" },
	pubKeyCredParams: [{ type: "public-key", alg: -257 }],
	encodedRegOpts:
		`{"rp":{"id":"localhost","name":"LocalHost!"},"user":{"id":["~b","AQEBAQ"],"name":"case2","displayName":"Case 2"},"challenge":["~b","AQEBAQEBAQEBAQEBAQEBAQ"],"pubKeyCredParams":[{"type":"public-key","alg":-257}],"timeout":300000,"excludeCredentials":[],"authenticatorSelection":{"authenticatorAttachment":"platform","residentKey":"required","userVerification":"required","requireResidentKey":true},"attestation":"none"}`,
	encodedRegCred:
		`{"rawId":["~b","rZ-d-bPQEPa80yLxQf7FXoia0RO-zn13kVVkg5dhWCA"],"response":{"clientDataJSON":["~b","eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQVFFQkFRRUJBUUVCQVFFQkFRRUJBUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"],"attestationObject":["~b","o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ0mWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAAAAAAAAAAAAAAAAAAAAAAAAACCtn535s9AQ9rzTIvFB_sVeiJrRE77OfXeRVWSDl2FYIKQBAwM5AQAgWQEApkwf-c4xcjULc7V9EfzWGxLdKD43y34IzeegEIbTojb-Vk7-DD82Xt7RulH7paXPBJIVXhsLRr4s1j82IAc-Dm9oasgBz0Bre1n7ERm0oozc8C4LKKS6X54XF4mwNtMBadVTlduRlUGnwd4bF3Ok56vLSipRJlCAtnP73i1rZpG1ekIBxf8OIeh5f1uPeW4SpkMjzeituh_vfyY933N31nQtWnqEAntJ1UTrT_HJPWeO1-gXmu0YcSOUBltX3LTKURLZWWn1PN6lMN3BE4ylzbUeyo09Fm5_IYiFTfjOuE1NCBSDYNvseSAOSfCzyhM9pAJ9l10wPH3ngCu6HADF2SFDAQAB"]}}`,
	credId: "rZ-d-bPQEPa80yLxQf7FXoia0RO-zn13kVVkg5dhWCA",
	encodedAuthOpts:
		`{"challenge":["~b","AQEBAQEBAQEBAQEBAQEBAQ"],"timeout":300000,"allowCredentials":[{"type":"public-key","id":["~b","rZ-d-bPQEPa80yLxQf7FXoia0RO-zn13kVVkg5dhWCA"]}],"userVerification":"required","attestation":"none"}`,
	encodedAuthCred:
		`{"rawId":["~b","rZ-d-bPQEPa80yLxQf7FXoia0RO-zn13kVVkg5dhWCA"],"response":{"clientDataJSON":["~b","eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVFFQkFRRUJBUUVCQVFFQkFRRUJBUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"],"authenticatorData":["~b","SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ"],"signature":["~b","HRy0h0jm22YmSAlR5P-QDq9x2RmRsyfKxCpJCBwJDs99jOGjwUl31ba_nhGTpuvnF-PHAZePn_OeQ6esH5vfL6eqKR6-Fbq55pcnu1s_JJT8RcQh1l7pRQfbcseD53xJlL7DyYX55gxMURNluRBgTgWiUc0HdcB5MPVCHxt528z-0vXHDLjO2Lzqt1Pbu_GzC7JbBsAudRQDij6e7jTCMjW-YaFlTfeBegwd1h9OpmeJEeEkj8TNc-wAK1TJahV0-TDXRV7EAlRVr4i_OJn1kVCWbAPVVgXW-Ep-my8WbQ1gvRjIjnUu8SLcYB8oZHbinhqwaHWOf32rdmUAAbx7Xw"],"userHandle":["~b","AQEBAQ"]}}`,
};

Deno.test({
	name: "ES256",
	async fn() {
		const { encodedRegCred, encodedAuthCred, challenge, allowedOrigins, allowedRPs, user } = ES256;
		const regCredential = jsonDecode(encodedRegCred) as RegistrationCredential;
		const { credId, pubKey, sigCount: sc1 } = await verifyRegistration({
			credential: regCredential,
			expectedChallenge: hexDecode(challenge),
			allowedOrigins,
			allowedRPs,
		});
		assertEquals(sc1, 0);
		const authCredential = jsonDecode(encodedAuthCred) as AuthenticationCredential;
		assertEquals(hexEncode(authCredential.rawId), hexEncode(credId));
		const { sigCount: sc2 } = await verifyAuthentication({
			expectedChallenge: hexDecode(challenge),
			credential: authCredential,
			allowedOrigins,
			allowedRPs,
			storedCredential: { userId: hexDecode(user.id), pubKey, sigCount: sc1 },
		});
		assertEquals(sc2, 1);
	},
});

Deno.test({
	name: "RS256",
	async fn() {
		const { encodedRegCred, encodedAuthCred, challenge, allowedOrigins, allowedRPs, user } = RS256;
		const regCredential = jsonDecode(encodedRegCred) as RegistrationCredential;
		const { credId, pubKey, sigCount: sc1 } = await verifyRegistration({
			credential: regCredential,
			expectedChallenge: hexDecode(challenge),
			allowedOrigins,
			allowedRPs,
		});
		assertEquals(sc1, 0);
		const authCredential = jsonDecode(encodedAuthCred) as AuthenticationCredential;
		assertEquals(hexEncode(authCredential.rawId), hexEncode(credId));
		const { sigCount: sc2 } = await verifyAuthentication({
			expectedChallenge: hexDecode(challenge),
			credential: authCredential,
			allowedOrigins,
			allowedRPs,
			storedCredential: { userId: hexDecode(user.id), pubKey, sigCount: sc1 },
		});
		assertEquals(sc2, 1);
	},
});
