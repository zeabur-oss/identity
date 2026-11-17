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

const form = document.getElementById("setup") as HTMLFormElement | null
const passwordForm = document.getElementById("setup-password") as HTMLFormElement | null
const passwordSetup = document.getElementById("password-setup")
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
  passwordSetup?.setAttribute("hidden", "")
  document.getElementById("upstream")?.setAttribute("hidden", "")
}

const failures: Record<string, string> = {
  "passkey-failed": "msgFailed",
  "device-passkey-needed": "msgDevicePasskey",
  "account-disabled": "msgDisabled",
  "ceremony-expired": "msgExpired",
  "passkey-exists": "msgExists",
  "admin-needs-passkey": "msgAdminPasskey",
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
  const label = document.querySelector<HTMLInputElement>("#label")?.value.trim()
  accepted(
    await post("/setup", { token, credential: registrationJson(credential), label: label || null }),
  )
}

/** The password typed, if it is long enough to send; otherwise says why not. */
function typedPassword(): string | null {
  const password = document.querySelector<HTMLInputElement>("#new-password")?.value ?? ""
  if ([...password].length >= 15) return password
  say("error", weakText("msgTooShort"))
  return null
}

function setPassword(event: SubmitEvent): void {
  event.preventDefault()
  if (!token || registering) return
  say("status", "")
  const password = typedPassword()
  if (password === null) return
  registering = true
  say("error", "")
  post("/setup/password", { token, password })
    .then(answered)
    .catch(() => say("error", text("msgError")))
    .finally(() => {
      registering = false
    })
}

function answered(reply: Reply): void {
  if (reply.ok) return done(true)
  const kind = problem(reply)
  if (kind !== "password-weak") return refused(kind)
  const weakness = String(reply.body.weakness)
  say("error", weakText(weaknesses[weakness] ?? "msgCommon"))
}

// Done: forget the token in the address bar and history, show the result. The backup advice is
// about passkeys only.
function done(password: boolean): void {
  say("status", "")
  window.history.replaceState(null, "", window.location.pathname + window.location.search)
  if (form) form.hidden = true
  passwordSetup?.setAttribute("hidden", "")
  document.getElementById("upstream")?.setAttribute("hidden", "")
  if (password) document.querySelector('[data-slot="backup"]')?.setAttribute("hidden", "")
  const view = document.getElementById("done")
  view?.removeAttribute("hidden")
  view?.focus()
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
    passwordSetup?.setAttribute("hidden", "")
  } else {
    passwordForm?.addEventListener("submit", setPassword)
    if (supported()) form.addEventListener("submit", register)
    else {
      document.getElementById("unsupported")?.removeAttribute("hidden")
      form.hidden = true
    }
  }
}
