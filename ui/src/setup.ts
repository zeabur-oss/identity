// Setup page: registers a passkey, or sets a password, with the one-time token from the URL
// fragment.
import {
  cancelled,
  creationOptions,
  messages,
  post,
  problem,
  type Reply,
  registrationJson,
  say,
  supported,
  upstreamButtons,
} from "./webauthn"
import type { PasswordSetUp, PasswordSetupOptions, Problem } from "./contract"

const form = document.getElementById("setup") as HTMLFormElement | null
const passwordForm = document.getElementById("setup-password") as HTMLFormElement | null
const alternatives = document.getElementById("alternatives")
const text = messages(form)
const weakText = messages(passwordForm)
const token = new URLSearchParams(window.location.hash.slice(1)).get("token")

// Keep the token when switching language: the links carry the fragment.
for (const link of document.querySelectorAll<HTMLAnchorElement>("a[data-lang-link]")) {
  link.hash = window.location.hash
}

// The link can no longer be used, so getting a new one is the only way on.
function invalid(): void {
  say("error", text("msgInvalid"))
  document.getElementById("new-link")?.removeAttribute("hidden")
  if (form) form.hidden = true
  passwordForm?.setAttribute("hidden", "")
  alternatives?.setAttribute("hidden", "")
}

const failures: Record<string, string> = {
  "passkey-failed": "msgFailed",
  "device-passkey-needed": "msgDevicePasskey",
  "account-disabled": "msgDisabled",
  "ceremony-expired": "msgExpired",
  "passkey-exists": "msgExists",
  "admin-needs-passkey": "msgAdminPasskey",
  "admin-needs-two-factor": "msgAdminTwoFactor",
  "code-failed": "msgCodeFailed",
  busy: "msgBusy",
}

const weaknesses: Record<string, string> = {
  "too-short": "msgTooShort",
  "too-long": "msgTooLong",
  common: "msgCommon",
  context: "msgContext",
}

/** A request the server refused, with the problem it named. */
class Refused extends Error {
  readonly kind: string
  constructor(kind: string) {
    super(kind)
    this.kind = kind
  }
}

/** Shows the message for a refused request, or the generic one. */
function refused(kind: string): void {
  if (kind === "setup-invalid") invalid()
  else say("error", text(failures[kind] ?? "msgError"))
}

/** Set while a passkey is registered or a password is set: the link works only once. */
let registering = false

function register(event: SubmitEvent): void {
  event.preventDefault()
  if (!token || registering) return
  registering = true
  say("error", "")
  say("status", text("msgWorking"))
  enrol(token)
    .then(() => done(false))
    .catch((error: unknown) => {
      say("status", "")
      if (error instanceof Refused) refused(error.kind)
      else say("error", text(cancelled(error) ? "msgCancelled" : "msgFailed"))
    })
    .finally(() => {
      registering = false
    })
}

/** `reply` if the server accepted the request; otherwise throws what it refused. */
function accepted(reply: Reply): Reply {
  if (!reply.ok) throw new Refused(problem(reply))
  return reply
}

async function enrol(token: string): Promise<void> {
  const started = accepted(await post("/setup/options", { token }))
  const credential = await navigator.credentials.create({
    publicKey: creationOptions(started.body),
  })
  if (!(credential instanceof PublicKeyCredential))
    throw new DOMException("no credential", "NotAllowedError")
  accepted(await post("/setup", { token, credential: registrationJson(credential), label: null }))
}

/** The password typed, if it is long enough to send; otherwise says why not. */
function typedPassword(): string | null {
  const password = document.querySelector<HTMLInputElement>("#new-password")?.value ?? ""
  if ([...password].length >= 15) return password
  say("error", weakText("msgTooShort"))
  return null
}

/** The sealed secret of the authenticator offered, once the options asked for one. */
let sealed: string | null = null

/** Asks what a password needs; shows the authenticator step when it needs one. */
async function passwordOptions(token: string): Promise<boolean> {
  const reply = await post("/setup/password/options", { token })
  if (!reply.ok) {
    refused(problem(reply))
    return false
  }
  const { totp } = reply.body as PasswordSetupOptions
  if (totp) {
    sealed = totp.sealed
    drawQr(totp.qr.size, totp.qr.path)
    const secret = document.getElementById("totp-secret")
    if (secret) secret.textContent = totp.secret.replace(/(.{4})(?=.)/g, "$1 ")
    document.getElementById("totp")?.removeAttribute("hidden")
  }
  return true
}

/** Draws the QR code as one SVG path; the page's CSP allows no image from elsewhere. */
function drawQr(size: number, d: string): void {
  const svg = document.getElementById("totp-qr")
  if (!svg) return
  const ns = "http://www.w3.org/2000/svg"
  svg.setAttribute("viewBox", `0 0 ${size} ${size}`)
  const path = document.createElementNS(ns, "path")
  path.setAttribute("d", d)
  path.setAttribute("fill", "currentColor")
  svg.replaceChildren(path)
}

function setPassword(event: SubmitEvent): void {
  event.preventDefault()
  if (!token || registering) return
  say("status", "")
  const password = typedPassword()
  if (password === null) return
  registering = true
  say("error", "")
  post("/setup/password", { token, password, totp: totpAnswer() })
    .then(answered)
    .catch(() => say("error", text("msgError")))
    .finally(() => {
      registering = false
    })
}

/** The sealed secret with the code typed for it, when the account needs an authenticator. */
function totpAnswer(): { sealed: string; code: string } | null {
  if (!sealed) return null
  const code = document.querySelector<HTMLInputElement>("#totp-code")?.value.trim() ?? ""
  return { sealed, code }
}

function answered(reply: Reply): void {
  if (reply.ok) return succeeded(reply)
  const kind = problem(reply)
  if (kind === "password-weak") say("error", weakText(weakness(reply)))
  else refused(kind)
}

/** The message key for the weakness the server named. */
function weakness(reply: Reply): string {
  return weaknesses[(reply.body as Problem).weakness ?? ""] ?? "msgCommon"
}

function succeeded(reply: Reply): void {
  const codes = (reply.body as PasswordSetUp).recovery_codes
  if (codes) showRecovery(codes)
  done(true)
}

function showRecovery(codes: string[]): void {
  const list = document.getElementById("recovery-codes")
  if (!list) return
  list.replaceChildren(
    ...codes.map((code) => {
      const line = document.createElement("span")
      line.textContent = code
      return line
    }),
  )
  document.getElementById("recovery")?.removeAttribute("hidden")
}

// Done: forget the token in the address bar and history, show the result. The backup advice is
// about passkeys only.
function done(password: boolean): void {
  say("status", "")
  window.history.replaceState(null, "", window.location.pathname + window.location.search)
  if (form) form.hidden = true
  passwordForm?.setAttribute("hidden", "")
  alternatives?.setAttribute("hidden", "")
  if (password) document.querySelector('[data-slot="backup"]')?.setAttribute("hidden", "")
  const view = document.getElementById("done")
  view?.removeAttribute("hidden")
  view?.focus()
}

/** Shows the password form alone, or the other ways back, with the passkey only if supported. */
function choosePassword(chosen: boolean): void {
  say("error", "")
  passwordForm?.toggleAttribute("hidden", !chosen)
  alternatives?.toggleAttribute("hidden", chosen)
  form?.toggleAttribute("hidden", chosen || !supported())
}

if (form) {
  // Linking an upstream account works without passkey support.
  if (token)
    upstreamButtons(() => ({ token }), text, {
      "setup-invalid": invalid,
      "admin-needs-passkey": () => say("error", text("msgAdminPasskey")),
      "account-disabled": () => say("error", text("msgDisabled")),
    })
  else document.getElementById("upstream")?.setAttribute("hidden", "")
  if (!token) {
    say("error", text("msgMissing"))
    document.getElementById("new-link")?.removeAttribute("hidden")
    form.hidden = true
    alternatives?.setAttribute("hidden", "")
  } else {
    passwordForm?.addEventListener("submit", setPassword)
    let asked: Promise<boolean> | null = null
    document.getElementById("use-password")?.addEventListener("click", () => {
      asked ??= passwordOptions(token).catch(() => {
        say("error", text("msgError"))
        return false
      })
      void asked.then((ok) => {
        if (!ok) {
          asked = null
          return
        }
        choosePassword(true)
        document.querySelector<HTMLInputElement>("#new-password")?.focus()
      })
    })
    document.getElementById("other-ways")?.addEventListener("click", () => choosePassword(false))
    if (supported()) form.addEventListener("submit", register)
    else {
      // Nothing above the other ways to set them apart from.
      document.getElementById("unsupported")?.removeAttribute("hidden")
      form.hidden = true
      alternatives?.querySelector('[data-slot="field-separator"]')?.setAttribute("hidden", "")
    }
  }
}
