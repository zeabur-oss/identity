// Shared helpers for the sign-in pages: WebAuthn JSON conversion (webauthn-rs wire format), JSON
// requests through the contract's route table, and accessible status messages. No HTML is ever
// written (Trusted Types: 'none').

import {
  type Accepted,
  type AccountChanged,
  type AccountSignedIn,
  type PasskeySignedIn,
  type PasswordSignedIn,
  type Problem,
  type Replies,
  type Requests,
  routes,
  type Step,
  type UnknownCredential,
  type UpstreamStarted,
  type WebAuthnJson,
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

/** A credential descriptor as webauthn-rs sends it: the ID is base64url. */
type WireDescriptor = Omit<PublicKeyCredentialDescriptor, "id"> & { id: string }

type WireCreation = Omit<
  PublicKeyCredentialCreationOptions,
  "challenge" | "user" | "excludeCredentials"
> & {
  challenge: string
  user: Omit<PublicKeyCredentialUserEntity, "id"> & { id: string }
  excludeCredentials?: WireDescriptor[]
}

type WireRequest = Omit<PublicKeyCredentialRequestOptions, "challenge" | "allowCredentials"> & {
  challenge: string
  allowCredentials?: WireDescriptor[]
}

function descriptors(
  list: WireDescriptor[] | undefined,
): PublicKeyCredentialDescriptor[] | undefined {
  return list?.map((d) => ({ ...d, id: fromBase64url(d.id) }))
}

/** `CreationChallengeResponse` JSON → options for `navigator.credentials.create`. */
export function creationOptions(json: WebAuthnJson): PublicKeyCredentialCreationOptions {
  const { publicKey: o } = json as { publicKey: WireCreation }
  return {
    ...o,
    challenge: fromBase64url(o.challenge),
    user: { ...o.user, id: fromBase64url(o.user.id) },
    excludeCredentials: descriptors(o.excludeCredentials),
  }
}

/** `RequestChallengeResponse` JSON → options for `navigator.credentials.get`. */
export function requestOptions(json: WebAuthnJson): PublicKeyCredentialRequestOptions {
  const { publicKey: o } = json as { publicKey: WireRequest }
  return {
    ...o,
    challenge: fromBase64url(o.challenge),
    allowCredentials: descriptors(o.allowCredentials) ?? [],
  }
}

/** A new credential → webauthn-rs `RegisterPublicKeyCredential`. */
export function registrationJson(credential: PublicKeyCredential): WebAuthnJson {
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
export function assertionJson(credential: PublicKeyCredential): WebAuthnJson {
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

/** A route the pages call, by its name in the contract's table. */
export type Route = keyof typeof routes

/** The `{name}` parameters of a route's path. */
type Params<P extends string> = P extends `${string}{${infer Name}}${infer Rest}`
  ? Record<Name, string> & Params<Rest>
  : Record<never, string>

type ParamsOf<K extends Route> = Params<(typeof routes)[K]["path"]>

/** A route's answer: its reply when `ok`, else a problem. */
export type Reply<K extends Route = Route> = {
  ok: boolean
  status: number
  body: Json & Partial<Replies[K]>
}

/** `path` with each `{name}` in it replaced by the encoded value `params` gives it. */
function fill(path: string, params: Record<string, string> = {}): string {
  return path.replace(/\{(\w+)\}/g, (_, name: string) => encodeURIComponent(params[name] ?? ""))
}

/** The JSON body of `response`, or an empty object when it has none. */
async function read(response: Response): Promise<Json> {
  try {
    return (await response.json()) as Json
  } catch {
    return {}
  }
}

/**
 * Calls `route` with the method and path the route table names, filling in the path's `{name}`
 * parameters from `params`. Same-origin only; the server also checks Fetch Metadata. A refusal
 * comes back in the page's language.
 */
export async function call<K extends Route>(
  route: K,
  body: Requests[K],
  ...[params]: keyof ParamsOf<K> extends never ? [] : [ParamsOf<K>]
): Promise<Reply<K>> {
  const { method, path } = routes[route]
  const response = await fetch(fill(path, params), {
    method,
    credentials: "same-origin",
    headers: {
      "content-type": "application/json",
      "accept-language": document.documentElement.lang || "en",
    },
    body: body === null ? undefined : JSON.stringify(body),
  })
  // The server's word for what it sent: the route's reply when ok, else a problem.
  const json = (await read(response)) as Reply<K>["body"]
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
 * token, linking) for its `data-provider` and follows the provider URL the server returns.
 * `steps` take over the steps the server names; otherwise its message shows.
 */
export function upstreamButtons(
  body: () => Requests["upstreamStart"],
  text: Text,
  steps: Partial<Record<Step, (reply: Reply) => void>> = {},
): void {
  for (const button of document.querySelectorAll<HTMLButtonElement>("button[data-provider]")) {
    const provider = button.dataset.provider ?? ""
    button.addEventListener("click", () => void startUpstream(provider, body(), text, steps))
  }
}

async function startUpstream(
  provider: string,
  body: Requests["upstreamStart"],
  text: Text,
  steps: Partial<Record<Step, (reply: Reply) => void>>,
): Promise<void> {
  say("error", "")
  say("status", text("msgWorking"))
  const reply = await call("upstreamStart", body, { provider }).catch(unreachable)
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

// The signal methods are WebAuthn Level 3 and missing from lib.dom; older browsers lack them.
declare global {
  interface PublicKeyCredentialConstructor {
    signalAllAcceptedCredentials?(options: Accepted): Promise<void>
    signalUnknownCredential?(options: UnknownCredential): Promise<void>
  }
}

/**
 * Passes the server's signals to the passkey provider (WebAuthn Level 3 §5.1.10), where the
 * browser supports them: `accepted` lists every credential the user still has, `unknownCredential`
 * names one the server does not know. Failures are ignored; they are hints. Safari with a passkey
 * manager extension never settles them, so this waits half a second at most.
 */
export async function signal(body: Json): Promise<void> {
  const { accepted } = body as AccountChanged | AccountSignedIn | PasskeySignedIn
  const { unknownCredential } = body as Problem
  const api = window.PublicKeyCredential
  const sent = [
    (async () => {
      if (accepted) await api?.signalAllAcceptedCredentials?.(accepted)
    })(),
    (async () => {
      if (unknownCredential) await api?.signalUnknownCredential?.(unknownCredential)
    })(),
  ]
  await Promise.race([Promise.allSettled(sent), new Promise((resolve) => setTimeout(resolve, 500))])
}
