// BASE64URL.
// Credit: https://gist.github.com/enepomnyaschih/72c423f727d395eeaa09697058238727
// Deno: https://github.com/denoland/deno_std/blob/main/encoding/base64url.ts

// deno-fmt-ignore
const base64abc = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9","+","/"];

export function base64Encode(data: ArrayBuffer | string): string {
	const uint8 = typeof data === "string"
		? new TextEncoder().encode(data)
		: data instanceof Uint8Array
		? data
		: new Uint8Array(data);
	let result = "", i;
	const l = uint8.length;
	for (i = 2; i < l; i += 3) {
		result += base64abc[uint8[i - 2] >> 2];
		result += base64abc[((uint8[i - 2] & 0x03) << 4) | (uint8[i - 1] >> 4)];
		result += base64abc[((uint8[i - 1] & 0x0f) << 2) | (uint8[i] >> 6)];
		result += base64abc[uint8[i] & 0x3f];
	}
	if (i === l + 1) {
		// 1 octet yet to write
		result += base64abc[uint8[i - 2] >> 2];
		result += base64abc[(uint8[i - 2] & 0x03) << 4];
		result += "==";
	}
	if (i === l) {
		// 2 octets yet to write
		result += base64abc[uint8[i - 2] >> 2];
		result += base64abc[((uint8[i - 2] & 0x03) << 4) | (uint8[i - 1] >> 4)];
		result += base64abc[(uint8[i - 1] & 0x0f) << 2];
		result += "=";
	}
	return result;
}

export function base64Decode(b64: string): Uint8Array {
	const binString = atob(b64);
	const size = binString.length;
	const bytes = new Uint8Array(size);
	for (let i = 0; i < size; i++) {
		bytes[i] = binString.charCodeAt(i);
	}
	return bytes;
}

export function base64urlEncode(data: ArrayBuffer | string): string {
	return base64Encode(data).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function addPaddingToBase64url(base64url: string): string {
	if (base64url.length % 4 === 2) return base64url + "==";
	if (base64url.length % 4 === 3) return base64url + "=";
	if (base64url.length % 4 === 1) {
		throw new TypeError("Illegal base64url string!");
	}
	return base64url;
}

function convertBase64urlToBase64(b64url: string): string {
	if (!/^[-_A-Z0-9]*?={0,2}$/i.test(b64url)) {
		// Contains characters not part of base64url spec.
		throw new TypeError("Failed to decode base64url: invalid character");
	}
	return addPaddingToBase64url(b64url).replace(/\-/g, "+").replace(/_/g, "/");
}

export function base64urlDecode(b64url: string): Uint8Array {
	return base64Decode(convertBase64urlToBase64(b64url));
}

// JSON

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

// CBOR

export { decode as cborDecode } from "https://deno.land/x/cbor@v1.4.1/index.js";
