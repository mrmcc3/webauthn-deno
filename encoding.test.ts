import { assertEquals } from "std/testing/asserts.ts";
import { base64urlEncode, hexDecode, hexEncode, jsonDecode, jsonEncode } from "./encoding.ts";

Deno.test({
	name: "test hex",
	fn() {
		const bytes = crypto.getRandomValues(new Uint8Array(32));
		const enc = hexEncode(bytes);
		assertEquals(enc.length, 64);
		assertEquals(typeof enc, "string");
		assertEquals(base64urlEncode(bytes), base64urlEncode(hexDecode(enc)));
	},
});

Deno.test({
	name: "test bytes in json",
	fn() {
		const bytes = crypto.getRandomValues(new Uint8Array(32));
		const arr = bytes.buffer;
		const enc = jsonEncode({ bytes, arr, nested: [bytes, arr] });
		const {
			bytes: b,
			arr: a,
			nested: [nb, na],
		} = jsonDecode(enc);
		assertEquals(base64urlEncode(bytes), base64urlEncode(b));
		assertEquals(base64urlEncode(bytes), base64urlEncode(nb));
		assertEquals(base64urlEncode(arr), base64urlEncode(a));
		assertEquals(base64urlEncode(arr), base64urlEncode(na));
	},
});
