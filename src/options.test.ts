import { assertEquals } from "https://deno.land/std@0.167.0/testing/asserts.ts";
import { jsonDecode, jsonEncode } from "./encoding.ts";
import {
	credentialCreationOptions,
	credentialRequestOptions,
	PublicKeyCredentialCreationOptions,
	PublicKeyCredentialRequestOptions,
} from "./options.ts";

Deno.test({
	name: "request options",
	fn() {
		const optsIn = credentialRequestOptions({ rpId: "localhost" });
		const optsOut = jsonDecode(jsonEncode(optsIn)) as PublicKeyCredentialRequestOptions;
		assertEquals(optsIn, optsOut);
		assertEquals(optsOut.challenge.byteLength >= 16, true);
		assertEquals(optsOut.userVerification, "required");
		assertEquals(optsOut.timeout, 300000);
		assertEquals(optsOut.attestation, "none");
	},
});

Deno.test({
	name: "creation options",
	fn() {
		const optsIn = credentialCreationOptions({
			rp: { id: "localhost", name: "Local Host!" },
			user: { id: new Uint8Array(16), name: "jdoe", displayName: "John Doe" },
			authenticatorSelection: {
				userVerification: "required",
				residentKey: "required",
				authenticatorAttachment: "platform",
			},
		});
		const optsOut = jsonDecode(jsonEncode(optsIn)) as PublicKeyCredentialCreationOptions;
		assertEquals(optsIn, optsOut);
		assertEquals(optsOut.challenge.byteLength >= 16, true);
		assertEquals(optsOut.timeout, 300000);
		assertEquals(optsOut.authenticatorSelection, {
			userVerification: "required",
			residentKey: "required",
			requireResidentKey: true,
			authenticatorAttachment: "platform",
		});
		assertEquals(optsOut.attestation, "none");
	},
});
