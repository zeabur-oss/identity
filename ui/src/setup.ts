// Setup page: registers a passkey with the one-time token from the URL fragment.
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
const text = messages(form)
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
  document.getElementById("upstream")?.setAttribute("hidden", "")
}

const failures: Record<string, string> = {
  "passkey-failed": "msgFailed",
  "device-passkey-needed": "msgDevicePasskey",
  "account-disabled": "msgDisabled",
  "ceremony-expired": "msgExpired",
  "passkey-exists": "msgExists",
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

/** Set while a passkey is being registered: a second press would start a second ceremony. */
let registering = false

function register(event: SubmitEvent): void {
  event.preventDefault()
  if (!token || registering) return
  registering = true
  say("error", "")
  say("status", text("msgWorking"))
  enrol(token)
    .then(done)
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

// Done: forget the token in the address bar and history, show the result.
function done(): void {
  say("status", "")
  window.history.replaceState(null, "", window.location.pathname + window.location.search)
  if (form) form.hidden = true
  document.getElementById("upstream")?.setAttribute("hidden", "")
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
  if (!supported()) {
    document.getElementById("unsupported")?.removeAttribute("hidden")
    form.hidden = true
  } else if (!token) {
    say("error", text("msgMissing"))
    document.getElementById("new-link")?.removeAttribute("hidden")
    form.hidden = true
  } else {
    form.addEventListener("submit", register)
  }
}
