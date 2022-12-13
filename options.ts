// Creation Options https://w3c.github.io/webauthn/#dictionary-makecredentialoptions

type AuthenticatorTransport = "usb" | "nfc" | "ble" | "hybrid" | "internal";
type UserVerificationRequirement = "required" | "preferred" | "discouraged";
type PublicKeyCredentialType = "public-key";

interface PublicKeyCredentialEntity {
	name: string;
}

interface PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
	id: string;
}

interface PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
	id: Uint8Array;
	displayName: string;
}

type AuthenticatorAttachment = "platform" | "cross-platform";
type ResidentKeyRequirement = "discouraged" | "preferred" | "required";

interface PublicKeyCredentialParameters {
	type: PublicKeyCredentialType;
	alg: string;
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

export function credentialCreationOptions(
	{
		rp,
		user,
		challenge = crypto.getRandomValues(new Uint8Array(16)),
		authenticatorSelection,
		excludeCredentials = [],
		timeout = authenticatorSelection?.userVerification === "discouraged" ? 120000 : 300000,
	}: CredentialCreationArgs,
): PublicKeyCredentialCreationOptions {
	if (challenge.byteLength < 16) {
		throw new Error("challenge should be at least 16 bytes");
	}
	if (authenticatorSelection?.requireResidentKey) {
		console.warn("This ");
	}
	if (authenticatorSelection) {
		if (authenticatorSelection.residentKey === "required") {
			authenticatorSelection.requireResidentKey = true;
		} else {
			delete authenticatorSelection.requireResidentKey;
		}
	}
	return {
		rp,
		user,
		challenge,
		pubKeyCredParams: [],
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
	userVerification = "preferred",
	timeout = userVerification === "discouraged" ? 120000 : 300000,
	allowCredentials = [],
	rpId,
}: CredentialRequestArgs = {}): PublicKeyCredentialRequestOptions {
	if (challenge.byteLength < 16) {
		throw new Error("challenge should be at least 16 bytes");
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
