// Shared helpers for the sign-in pages: WebAuthn JSON conversion (webauthn-rs wire format), JSON
// requests, and accessible status messages. No HTML is ever written (Trusted Types: 'none').

import type {
  Accepted,
  AccountChanged,
  AccountSignedIn,
  PasskeySignedIn,
  PasswordSignedIn,
  Problem,
  Step,
  UnknownCredential,
  UpstreamStarted,
} from "./contract"

type Json = Record<string, unknown>

/** A page's messages, from the `data-msg-*` attributes on `element`; a missing one is empty. */
export type Text = (key: string) => string

export function messages(element: HTMLElement | null): Text {
  const dataset = element?.dataset ?? {}
  return (key) => dataset[key] ?? ""
}

function toBase64url(buffer: ArrayBuffer | ArrayBufferView): string {
  const bytes =
    buffer instanceof ArrayBuffer
      ? new Uint8Array(buffer)
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function fromBase64url(value: string): ArrayBuffer {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=")
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

type Descriptor = { id: string; type: string; transports?: string[] }

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined
  return (list as Descriptor[]).map(
    (d) => ({ ...d, id: fromBase64url(d.id) }) as PublicKeyCredentialDescriptor,
  )
}

/** `CreationChallengeResponse` JSON → options for `navigator.credentials.create`. */
export function creationOptions(json: Json): PublicKeyCredentialCreationOptions {
  const o = json.publicKey as Json
  const user = o.user as Json
  return {
    ...(o as unknown as PublicKeyCredentialCreationOptions),
    challenge: fromBase64url(o.challenge as string),
    user: {
      ...(user as unknown as PublicKeyCredentialUserEntity),
      id: fromBase64url(user.id as string),
    },
    excludeCredentials: descriptors(o.excludeCredentials),
  }
}

/** `RequestChallengeResponse` JSON → options for `navigator.credentials.get`. */
export function requestOptions(json: Json): PublicKeyCredentialRequestOptions {
  const o = json.publicKey as Json
  return {
    ...(o as unknown as PublicKeyCredentialRequestOptions),
    challenge: fromBase64url(o.challenge as string),
    allowCredentials: descriptors(o.allowCredentials) ?? [],
  }
}

/** A new credential → webauthn-rs `RegisterPublicKeyCredential`. */
export function registrationJson(credential: PublicKeyCredential): Json {
  const response = credential.response as AuthenticatorAttestationResponse
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: toBase64url(response.attestationObject),
      clientDataJSON: toBase64url(response.clientDataJSON),
      transports:
        typeof response.getTransports === "function" ? response.getTransports() : undefined,
    },
    extensions: credential.getClientExtensionResults(),
  }
}

/** An assertion → webauthn-rs `PublicKeyCredential`. */
export function assertionJson(credential: PublicKeyCredential): Json {
  const response = credential.response as AuthenticatorAssertionResponse
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: toBase64url(response.authenticatorData),
      clientDataJSON: toBase64url(response.clientDataJSON),
      signature: toBase64url(response.signature),
      userHandle: response.userHandle ? toBase64url(response.userHandle) : null,
    },
    extensions: credential.getClientExtensionResults(),
  }
}

export type Reply = { ok: boolean; status: number; body: Json }

/** The endpoint a control posts to, from its `data-<name>` attribute. */
export function endpoint(element: Element | null | undefined, name = "post"): string {
  return element instanceof HTMLElement ? (element.dataset[name] ?? "") : ""
}

/**
 * POSTs JSON to the issuer. Same-origin only; the server also checks Fetch Metadata. A refusal
 * comes back in the page's language.
 */
export async function post(path: string, body: Json): Promise<Reply> {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "content-type": "application/json",
      "accept-language": document.documentElement.lang || "en",
    },
    body: JSON.stringify(body),
  })
  let json: Json = {}
  try {
    json = (await response.json()) as Json
  } catch {
    // Empty or non-JSON body.
  }
  return { ok: response.ok, status: response.status, body: json }
}

/** The reply for a request that never reached the server. */
const unreachable = (): Reply => ({ ok: false, status: 0, body: {} })

/** The step the server named for a refused request, if any. */
export function next(reply: Reply): Step | undefined {
  return (reply.body as Partial<Problem>).next
}

/** Whether the server says the page shows a list that changed in the meantime. */
export function stale(reply: Reply): boolean {
  return (reply.body as Partial<Problem>).refresh === true
}

/** The server's message for a refused request, or the generic one when there is none. */
export function explain(reply: Reply, text: Text): string {
  return (reply.body as Partial<Problem>).detail || text("msgError")
}

export function supported(): boolean {
  return (
    typeof window.PublicKeyCredential === "function" &&
    typeof navigator.credentials?.create === "function"
  )
}

/** Writes `text` into a live region (textContent only). */
export function write(element: HTMLElement | null, text: string): void {
  if (element) element.textContent = text
}

/** Writes `text` into the page's status or error region. */
export function say(id: "status" | "error", text: string): void {
  write(document.getElementById(id), text)
}

/** The URL in a reply that sends the browser elsewhere, if it has one. */
export function redirect(reply: Reply): string | null {
  const body = reply.body as PasskeySignedIn | PasswordSignedIn | UpstreamStarted
  return (reply.ok && body.redirect_to) || null
}

/**
 * Wires the "Continue with <provider>" buttons: each starts an upstream sign-in (or, with a
 * token, linking) at its `data-start` endpoint and follows the provider URL the server returns.
 * `steps` take over the steps the server names; otherwise its message shows.
 */
export function upstreamButtons(
  body: () => Json,
  text: Text,
  steps: Partial<Record<Step, (reply: Reply) => void>> = {},
): void {
  for (const button of document.querySelectorAll<HTMLButtonElement>("button[data-start]")) {
    const start = endpoint(button, "start")
    button.addEventListener("click", () => void startUpstream(start, body(), text, steps))
  }
}

async function startUpstream(
  start: string,
  body: Json,
  text: Text,
  steps: Partial<Record<Step, (reply: Reply) => void>>,
): Promise<void> {
  say("error", "")
  say("status", text("msgWorking"))
  const reply = await post(start, body).catch(unreachable)
  const to = redirect(reply)
  if (to) return window.location.assign(to)
  say("status", "")
  const step = next(reply)
  const handler = step && steps[step]
  if (handler) handler(reply)
  else say("error", explain(reply, text))
}

/** Whether an error is the user cancelling or the browser's timeout. */
export function cancelled(error: unknown): boolean {
  return (
    error instanceof DOMException &&
    (error.name === "NotAllowedError" || error.name === "AbortError")
  )
}

type Signals = {
  signalAllAcceptedCredentials?: (options: Accepted) => Promise<void>
  signalUnknownCredential?: (options: UnknownCredential) => Promise<void>
}

/**
 * Passes the server's signals to the passkey provider (WebAuthn Level 3 §5.1.10), where the
 * browser supports them: `accepted` lists every credential the user still has, `unknownCredential`
 * names one the server does not know. Failures are ignored; they are hints. Safari with a passkey
 * manager extension never settles them, so this waits half a second at most.
 */
export async function signal(body: Json): Promise<void> {
  const sent = [
    send(
      "signalAllAcceptedCredentials",
      (body as AccountChanged | AccountSignedIn | PasskeySignedIn).accepted,
    ),
    send("signalUnknownCredential", (body as Problem).unknownCredential),
  ]
  await Promise.race([Promise.allSettled(sent), new Promise((resolve) => setTimeout(resolve, 500))])
}

async function send<K extends keyof Signals>(
  name: K,
  options: Parameters<NonNullable<Signals[K]>>[0] | undefined,
): Promise<void> {
  const api = window.PublicKeyCredential as unknown as Signals | undefined
  const method = api?.[name] as ((options: object) => Promise<void>) | undefined
  if (options && typeof method === "function") await method.call(api, options)
}
