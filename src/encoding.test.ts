import { assertEquals } from "std/testing/asserts.ts";
import {
	base64urlDecode,
	base64urlEncode,
	cborDecode,
	hexDecode,
	hexEncode,
	jsonDecode,
	jsonEncode,
} from "./encoding.ts";

Deno.test({
	name: "hex",
	fn() {
		const bytes = crypto.getRandomValues(new Uint8Array(32));
		const enc = hexEncode(bytes);
		assertEquals(enc.length, 64);
		assertEquals(typeof enc, "string");
		assertEquals(base64urlEncode(bytes), base64urlEncode(hexDecode(enc)));
	},
});

Deno.test({
	name: "json",
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

Deno.test({
	name: "cbor",
	fn() {
		const attObj = base64urlDecode(
			"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAILISGkTaRrjTNAaB-eUgdpq9UkMX7bUp48VUUVTYLn13pQECAyYgASFYIMYgVZSLVApLJVhP5gUUnrh1lBPMGb7lpi37iQx16mn7IlggOROohidXDm1xzHYgqRzcIno6PztoqglEIbyC6TvClnA",
		);
		const res = cborDecode(attObj);
		assertEquals(res.fmt, "none");
		assertEquals(res.attStmt, {});
		assertEquals(res.authData.byteLength, 164);
	},
});
