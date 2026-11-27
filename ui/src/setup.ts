// Setup page: registers a passkey, or sets a password, with the one-time token from the URL
// fragment.
import {
  cancelled,
  creationOptions,
  endpoint,
  explain,
  messages,
  next,
  post,
  type Reply,
  registrationJson,
  say,
  supported,
  upstreamButtons,
} from "./webauthn"
import { longEnough } from "./password"
import { showEnrolment, showRecovery, totpAnswer } from "./totp"
import type { PasswordSetUp, PasswordSetupOptions } from "./contract"

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
function invalid(message: string): void {
  say("error", message)
  document.getElementById("new-link")?.removeAttribute("hidden")
  if (form) form.hidden = true
  passwordForm?.setAttribute("hidden", "")
  alternatives?.setAttribute("hidden", "")
}

/** A request the server refused. */
class Refused extends Error {
  readonly reply: Reply
  constructor(reply: Reply) {
    super(reply.status.toString())
    this.reply = reply
  }
}

/** Shows the server's message for a refused request, or the new-link step it names. */
function refused(reply: Reply): void {
  if (next(reply) === "new-link") invalid(explain(reply, text))
  else say("error", explain(reply, text))
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
      if (error instanceof Refused) refused(error.reply)
      else say("error", text(cancelled(error) ? "msgCancelled" : "msgFailed"))
    })
    .finally(() => {
      registering = false
    })
}

/** `reply` if the server accepted the request; otherwise throws what it refused. */
function accepted(reply: Reply): Reply {
  if (!reply.ok) throw new Refused(reply)
  return reply
}

async function enrol(token: string): Promise<void> {
  const started = accepted(await post(endpoint(form, "options"), { token }))
  const credential = await navigator.credentials.create({
    publicKey: creationOptions(started.body),
  })
  if (!(credential instanceof PublicKeyCredential))
    throw new DOMException("no credential", "NotAllowedError")
  accepted(
    await post(endpoint(form), { token, credential: registrationJson(credential), label: null }),
  )
}

/** The password typed, if it is long enough to send; otherwise says why not. */
function typedPassword(): string | null {
  const input = document.querySelector<HTMLInputElement>("#new-password")
  if (longEnough(input)) return input.value
  say("error", weakText("msgTooShort"))
  return null
}

/** The sealed secret of the authenticator offered, once the options asked for one. */
let sealed: string | null = null

/** Asks what a password needs; shows the authenticator step when it needs one. */
async function passwordOptions(token: string): Promise<boolean> {
  const reply = await post(endpoint(document.getElementById("use-password")), { token })
  if (!reply.ok) {
    refused(reply)
    return false
  }
  const { totp } = reply.body as PasswordSetupOptions
  if (totp) sealed = showEnrolment(totp)
  return true
}

function setPassword(event: SubmitEvent): void {
  event.preventDefault()
  if (!token || registering) return
  say("status", "")
  const password = typedPassword()
  if (password === null) return
  registering = true
  say("error", "")
  post(endpoint(passwordForm), { token, password, totp: totpAnswer(sealed) })
    .then(answered)
    .catch(() => say("error", text("msgError")))
    .finally(() => {
      registering = false
    })
}

function answered(reply: Reply): void {
  if (reply.ok) succeeded(reply)
  else refused(reply)
}

function succeeded(reply: Reply): void {
  const codes = (reply.body as PasswordSetUp).recovery_codes
  if (codes) showRecovery(codes)
  done(true)
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
      "new-link": (reply) => invalid(explain(reply, text)),
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
