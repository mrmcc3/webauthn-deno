import { decode as hexDecodeBytes, encode as hexEncodeBytes } from "std/encoding/hex.ts";
import { decode as base64urlDecode, encode as base64urlEncode } from "std/encoding/base64url.ts";

export function hexDecode(input: string) {
	return hexDecodeBytes(new TextEncoder().encode(input));
}

export function hexEncode(input: ArrayBuffer) {
	return new TextDecoder().decode(hexEncodeBytes(new Uint8Array(input)));
}

// deno-lint-ignore no-explicit-any
function replacer(this: any, key: string) {
	const val = this[key];
	if (val instanceof ArrayBuffer) {
		return ["~b", base64urlEncode(val)];
	} else if (ArrayBuffer.isView(val)) {
		return ["~b", base64urlEncode(val.buffer)];
	}
	return val;
}

// deno-lint-ignore no-explicit-any
export function jsonEncode(data: any) {
	return JSON.stringify(data, replacer);
}

// deno-lint-ignore no-explicit-any
function reviver(_key: string, val: any) {
	if (Array.isArray(val) && val.length === 2 && val[0] === "~b") {
		return base64urlDecode(val[1]);
	}
	return val;
}

export function jsonDecode(text: string) {
	return JSON.parse(text, reviver);
}

export { decode as cborDecode, encode as cborEncode } from "cbor-x/index.js";
export { decode as base64urlDecode, encode as base64urlEncode } from "std/encoding/base64url.ts";
