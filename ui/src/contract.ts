// Generated from the server's request and reply types and its routes; do not edit.
// Regenerate: ZEABUR_IDENTITY_WRITE_CONTRACT=1 cargo test -p zeabur-identity-signin contract

/** The user's registered credentials, for `signalAllAcceptedCredentials` (WebAuthn Level 3 §5.1.10.2). Only a complete list read from storage is sent; an empty one never is, so a failed or partial read cannot make a provider hide working passkeys. */
export type Accepted = {
  rpId: string
  userId: string
  allAcceptedCredentialIds: string[]
}

export type AccountChanged = {
  /** The session viewing the page was signed out by this change. */
  signed_out: boolean
  accepted?: Accepted
}

/** The reply to a change on the account page that makes recovery codes. */
export type AccountRecoveryCodes = {
  /** Shown once; only their hashes are stored. */
  recovery_codes?: string[]
}

export type AccountSignedIn = {
  accepted?: Accepted
}

export type AddPasskeyRequest = {
  /** The new credential, in the webauthn-rs `RegisterPublicKeyCredential` form. */
  credential: WebAuthnJson
  label?: string | null
}

export type AddPasswordRequest = {
  password: string
  /** The authenticator, when the options asked for one. */
  totp?: TotpRequest | null
}

export type ChangePasswordRequest = {
  current: string
  new: string
}

export type ConfirmRequest = {
  /** The current password. Without it, the change needs a recent passkey confirmation. */
  current?: string | null
  /** A code from the current authenticator, or a recovery code, with `current`. */
  code?: string | null
}

export type LinkStartRequest = {
  provider: string
}

export type PasskeyAssertionRequest = {
  /** The assertion, in the webauthn-rs `PublicKeyCredential` form. */
  credential: WebAuthnJson
}

export type PasskeySetUp = {
  username: string
}

export type PasskeySetupOptionsRequest = {
  token: string
}

export type PasskeySetupRequest = {
  token: string
  /** The new credential, in the webauthn-rs `RegisterPublicKeyCredential` form. */
  credential: WebAuthnJson
  label?: string | null
}

export type PasskeySignInRequest = {
  /** The assertion, in the webauthn-rs `PublicKeyCredential` form. */
  credential: WebAuthnJson
}

export type PasskeySignedIn = {
  redirect_to: string
  accepted?: Accepted
}

export type PasswordSetUp = {
  username: string
  /** Shown once; only their hashes are stored. */
  recovery_codes?: string[]
}

export type PasswordSetupOptions = {
  /** An authenticator to add, when the settings need a second factor for this user. */
  totp: TotpEnrolment | null
}

export type PasswordSetupOptionsRequest = {
  token: string
}

export type PasswordSetupRequest = {
  token: string
  password: string
  /** The authenticator, when the options asked for one. */
  totp?: TotpRequest | null
}

export type PasswordSignInRequest = {
  username: string
  password: string
  /** A TOTP or recovery code, after a `code-needed` answer. */
  code?: string | null
}

export type PasswordSignedIn = {
  redirect_to: string
}

/** The JSON body of a problem (RFC 9457 §3), with every extension member (§3.2) any problem carries. Each member is present only on the problems that set it. */
export type Problem = {
  /** `urn:zeabur-identity:problem:<kind>`. */
  type: string
  title: string
  status: number
  /** The message to show, in the language of the request's `Accept-Language`. */
  detail: string
  /** The page shows a list that changed in the meantime: reload it, then show `detail`. */
  refresh?: boolean
  /** The step the page moves to, in place of showing `detail`. */
  next?: Step
  /** Why a new password was refused (`password-weak`). */
  weakness?: Weakness
  /** The credential the relying party does not know (`passkey-failed`), for `signalUnknownCredential` (WebAuthn Level 3 §5.1.10.1). */
  unknownCredential?: UnknownCredential
}

/** A QR code as one SVG path in a `size` × `size` box, quiet zone included. */
export type Qr = {
  size: number
  path: string
}

export type RemovePasswordRequest = {
  current: string
}

export type RenamePasskeyRequest = {
  label: string
}

export type ReplaceAuthenticatorRequest = {
  /** The current password. Without it, the change needs a recent passkey confirmation. */
  current?: string | null
  /** A code from the current authenticator, or a recovery code, with `current`. */
  code?: string | null
  /** The new authenticator: `sealed` from its options, and its current code. */
  totp: TotpRequest
}

/** The step a page moves to after a problem, in place of showing it. */
export type Step = "code" | "ended" | "new-link" | "reauth"

export type TotpEnrolment = {
  /** The secret in base32, for typing into the app. */
  secret: string
  /** The same secret in groups of four, as the page shows it. */
  secret_display: string
  /** The `otpauth://` URI the QR code holds. */
  uri: string
  qr: Qr
  /** The secret sealed to the setup token, sent back with the password. */
  sealed: string
}

export type TotpRequest = {
  /** `sealed` from the options. */
  sealed: string
  /** The current code from the authenticator app. */
  code: string
}

/** The argument of `PublicKeyCredential.signalUnknownCredential()`. */
export type UnknownCredential = {
  /** The relying party ID. */
  rpId: string
  /** The credential ID, base64url. */
  credentialId: string
}

export type UpstreamStartRequest = {
  token?: string | null
}

export type UpstreamStarted = {
  redirect_to: string
}

/** Why a new password is refused. */
export type Weakness = "too-short" | "too-long" | "common" | "context"

/** A webauthn-rs value in its JSON form; `ui/src/webauthn.ts` converts it. */
export type WebAuthnJson = Record<string, unknown>

/** The JSON routes the pages call. The caller fills in the parameters in braces. */
export const routes = {
  loginOptions: { method: "POST", path: "/login/options" },
  login: { method: "POST", path: "/login" },
  passwordLogin: { method: "POST", path: "/login/password" },
  upstreamStart: { method: "POST", path: "/upstream/{provider}/start" },
  setupOptions: { method: "POST", path: "/setup/options" },
  setup: { method: "POST", path: "/setup" },
  passwordSetupOptions: { method: "POST", path: "/setup/password/options" },
  passwordSetup: { method: "POST", path: "/setup/password" },
  sessionOptions: { method: "POST", path: "/account/session/options" },
  signIn: { method: "POST", path: "/account/session" },
  passwordSignIn: { method: "POST", path: "/account/session/password" },
  signOut: { method: "DELETE", path: "/account/session" },
  reauthOptions: { method: "POST", path: "/account/reauth/options" },
  reauth: { method: "POST", path: "/account/reauth" },
  addPasskeyOptions: { method: "POST", path: "/account/passkeys/options" },
  addPasskey: { method: "POST", path: "/account/passkeys" },
  renamePasskey: { method: "PATCH", path: "/account/passkeys/{name}" },
  removePasskey: { method: "DELETE", path: "/account/passkeys/{name}" },
  revokeOtherSessions: { method: "DELETE", path: "/account/sessions" },
  revokeSession: { method: "DELETE", path: "/account/sessions/{name}" },
  link: { method: "POST", path: "/account/links/start" },
  unlink: { method: "DELETE", path: "/account/links/{name}" },
  addPasswordOptions: { method: "POST", path: "/account/password/options" },
  addPassword: { method: "POST", path: "/account/password" },
  changePassword: { method: "PUT", path: "/account/password" },
  removePassword: { method: "DELETE", path: "/account/password" },
  authenticatorOptions: { method: "POST", path: "/account/authenticator/options" },
  replaceAuthenticator: { method: "PUT", path: "/account/authenticator" },
  regenerateRecoveryCodes: { method: "POST", path: "/account/recovery-codes" },
} as const

/** The body each route takes; `null` when it takes none. */
export type Requests = {
  loginOptions: null
  login: PasskeySignInRequest
  passwordLogin: PasswordSignInRequest
  upstreamStart: UpstreamStartRequest
  setupOptions: PasskeySetupOptionsRequest
  setup: PasskeySetupRequest
  passwordSetupOptions: PasswordSetupOptionsRequest
  passwordSetup: PasswordSetupRequest
  sessionOptions: null
  signIn: PasskeyAssertionRequest
  passwordSignIn: PasswordSignInRequest
  signOut: null
  reauthOptions: null
  reauth: PasskeyAssertionRequest
  addPasskeyOptions: null
  addPasskey: AddPasskeyRequest
  renamePasskey: RenamePasskeyRequest
  removePasskey: null
  revokeOtherSessions: null
  revokeSession: null
  link: LinkStartRequest
  unlink: null
  addPasswordOptions: null
  addPassword: AddPasswordRequest
  changePassword: ChangePasswordRequest
  removePassword: RemovePasswordRequest
  authenticatorOptions: null
  replaceAuthenticator: ReplaceAuthenticatorRequest
  regenerateRecoveryCodes: ConfirmRequest
}

/** The body each route answers with when it succeeds. */
export type Replies = {
  loginOptions: WebAuthnJson
  login: PasskeySignedIn
  passwordLogin: PasswordSignedIn
  upstreamStart: UpstreamStarted
  setupOptions: WebAuthnJson
  setup: PasskeySetUp
  passwordSetupOptions: PasswordSetupOptions
  passwordSetup: PasswordSetUp
  sessionOptions: WebAuthnJson
  signIn: AccountSignedIn
  passwordSignIn: AccountSignedIn
  signOut: AccountChanged
  reauthOptions: WebAuthnJson
  reauth: AccountChanged
  addPasskeyOptions: WebAuthnJson
  addPasskey: AccountChanged
  renamePasskey: AccountChanged
  removePasskey: AccountChanged
  revokeOtherSessions: AccountChanged
  revokeSession: AccountChanged
  link: UpstreamStarted
  unlink: AccountChanged
  addPasswordOptions: PasswordSetupOptions
  addPassword: AccountRecoveryCodes
  changePassword: AccountChanged
  removePassword: AccountChanged
  authenticatorOptions: TotpEnrolment
  replaceAuthenticator: AccountRecoveryCodes
  regenerateRecoveryCodes: AccountRecoveryCodes
}
