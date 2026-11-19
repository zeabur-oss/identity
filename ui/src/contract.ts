// Generated from the server's reply types; do not edit.
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

export type AccountSignedIn = {
  accepted?: Accepted
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

/** The argument of `PublicKeyCredential.signalUnknownCredential()`. */
export type UnknownCredential = {
  /** The relying party ID. */
  rpId: string
  /** The credential ID, base64url. */
  credentialId: string
}

export type UpstreamStarted = {
  redirect_to: string
}

/** Why a new password is refused. */
export type Weakness = "too-short" | "too-long" | "common" | "context"
