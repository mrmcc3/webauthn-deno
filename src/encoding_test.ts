import { assertEquals } from "https://deno.land/std@0.167.0/testing/asserts.ts";
import {
	base64urlDecode,
	base64urlEncode,
	cborDecode,
	jsonDecode,
	jsonEncode,
} from "./encoding.ts";

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
		assertEquals(bytes, b);
		assertEquals(bytes, nb);
		assertEquals(new Uint8Array(arr), new Uint8Array(a));
		assertEquals(new Uint8Array(arr), na);
	},
});

Deno.test({
	name: "cbor",
	fn() {
		const attEnc =
			"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAILISGkTaRrjTNAaB-eUgdpq9UkMX7bUp48VUUVTYLn13pQECAyYgASFYIMYgVZSLVApLJVhP5gUUnrh1lBPMGb7lpi37iQx16mn7IlggOROohidXDm1xzHYgqRzcIno6PztoqglEIbyC6TvClnA";
		const attObj = base64urlDecode(attEnc);
		const res = cborDecode(attObj);
		assertEquals(res.fmt, "none");
		assertEquals(res.attStmt, {});
		assertEquals(res.authData.byteLength, 164);
		assertEquals(base64urlEncode(attObj), attEnc);
	},
});
