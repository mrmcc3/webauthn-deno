import { algorithms } from "./keys.ts";

// Creation Options https://w3c.github.io/webauthn/#dictionary-makecredentialoptions

type AuthenticatorTransport = "usb" | "nfc" | "ble" | "hybrid" | "internal";
type UserVerificationRequirement = "required" | "preferred" | "discouraged";
type PublicKeyCredentialType = "public-key";

interface PublicKeyCredentialEntity {
	name: string;
}

interface PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
	id?: string;
}

interface PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
	id: Uint8Array;
	displayName: string;
}

type AuthenticatorAttachment = "platform" | "cross-platform";
type ResidentKeyRequirement = "discouraged" | "preferred" | "required";

interface PublicKeyCredentialParameters {
	type: PublicKeyCredentialType;
	alg: number;
}

interface AuthenticatorSelectionCriteria {
	authenticatorAttachment?: AuthenticatorAttachment;
	residentKey?: ResidentKeyRequirement;
	/**
	 * @deprecated use 'residentKey' instead
	 */
	requireResidentKey?: boolean;
	userVerification?: UserVerificationRequirement;
}

export interface PublicKeyCredentialCreationOptions {
	rp: PublicKeyCredentialRpEntity;
	user: PublicKeyCredentialUserEntity;
	challenge: Uint8Array;
	pubKeyCredParams: PublicKeyCredentialParameters[];
	timeout: number;
	excludeCredentials?: PublicKeyCredentialDescriptor[];
	authenticatorSelection?: AuthenticatorSelectionCriteria;
	attestation: "none"; // only support none
	// no extensions
}

interface CredentialCreationArgs {
	rp: PublicKeyCredentialRpEntity;
	user: PublicKeyCredentialUserEntity;
	challenge?: Uint8Array;
	timeout?: number;
	excludeCredentials?: PublicKeyCredentialDescriptor[];
	authenticatorSelection?: AuthenticatorSelectionCriteria;
}

const pubKeyCredParams = Array.from(algorithms.keys()).map((alg) => ({
	alg,
	type: "public-key",
} as PublicKeyCredentialParameters));

export function credentialCreationOptions(
	{
		rp,
		user,
		challenge = crypto.getRandomValues(new Uint8Array(16)),
		authenticatorSelection = { userVerification: "required", residentKey: "required" },
		excludeCredentials = [],
		timeout = 300000,
	}: CredentialCreationArgs,
): PublicKeyCredentialCreationOptions {
	if (challenge.byteLength < 16) {
		throw new Error("challenge should be at least 16 bytes");
	}
	// currently only support user verified authenticators with resident keys.
	if (authenticatorSelection.userVerification !== "required") {
		throw new Error(
			"userVerification must be set to required. other options are currently not supported",
		);
	}
	if (authenticatorSelection.residentKey !== "required") {
		throw new Error(
			"residentKey must be set to required. other options are currently not supported",
		);
	}
	authenticatorSelection.requireResidentKey = true;
	return {
		rp,
		user,
		challenge,
		pubKeyCredParams,
		timeout,
		excludeCredentials,
		authenticatorSelection,
		attestation: "none",
	};
}

// Assertion Options https://w3c.github.io/webauthn/#dictionary-assertion-options

interface PublicKeyCredentialDescriptor {
	type: PublicKeyCredentialType;
	id: Uint8Array;
	transports?: AuthenticatorTransport[];
}

export interface PublicKeyCredentialRequestOptions {
	challenge: Uint8Array;
	timeout: number; // defaults to recommendations in spec.
	rpId?: string;
	allowCredentials: PublicKeyCredentialDescriptor[];
	userVerification: UserVerificationRequirement;
	attestation: "none"; // only support none
	// don't support extensions
}

interface CredentialRequestArgs {
	challenge?: Uint8Array;
	timeout?: number;
	rpId?: string;
	allowCredentials?: PublicKeyCredentialDescriptor[];
	userVerification?: UserVerificationRequirement;
}

export function credentialRequestOptions({
	challenge = crypto.getRandomValues(new Uint8Array(16)),
	userVerification = "required",
	timeout = 300000,
	allowCredentials = [],
	rpId,
}: CredentialRequestArgs = {}): PublicKeyCredentialRequestOptions {
	if (challenge.byteLength < 16) {
		throw new Error("challenge should be at least 16 bytes");
	}
	if (userVerification !== "required") {
		throw new Error(
			"userVerification must be set to required. other options are currently not supported",
		);
	}
	return {
		challenge,
		timeout,
		rpId,
		allowCredentials,
		userVerification,
		attestation: "none",
	};
}
