import { assertEquals } from "std/testing/asserts.ts";
import { jsonDecode, jsonEncode } from "./encoding.ts";
import {
	credentialCreationOptions,
	credentialRequestOptions,
	PublicKeyCredentialCreationOptions,
	PublicKeyCredentialRequestOptions,
} from "./options.ts";

Deno.test({
	name: "test credential request options",
	fn() {
		const optsIn = credentialRequestOptions({ rpId: "localhost" });
		const optsOut = jsonDecode(jsonEncode(optsIn)) as PublicKeyCredentialRequestOptions;
		assertEquals(optsIn, optsOut);
		assertEquals(optsOut.challenge.byteLength >= 16, true);
		assertEquals(optsOut.userVerification, "preferred");
		assertEquals(optsOut.timeout, 300000);
		assertEquals(optsOut.attestation, "none");
	},
});

Deno.test({
	name: "test credential creation options",
	fn() {
		const optsIn = credentialCreationOptions({
			rp: { id: "localhost", name: "Local Host!" },
			user: { id: new Uint8Array(16), name: "jdoe", displayName: "John Doe" },
			authenticatorSelection: {
				residentKey: "required",
			},
		});
		const optsOut = jsonDecode(jsonEncode(optsIn)) as PublicKeyCredentialCreationOptions;
		assertEquals(optsIn, optsOut);
		assertEquals(optsOut.challenge.byteLength >= 16, true);
		assertEquals(optsOut.timeout, 300000);
		assertEquals(optsOut.authenticatorSelection, {
			residentKey: "required",
			requireResidentKey: true,
		});
		assertEquals(optsOut.attestation, "none");
	},
});
