// Sign-in page: username and password, then an authenticator code if the account has one;
// passkey autofill (conditional mediation) on the username field, and a passkey button.
import {
  assertionJson,
  cancelled,
  messages,
  post,
  problem,
  type Reply,
  redirect,
  requestOptions,
  say,
  signal,
  supported,
  upstreamButtons,
} from "./webauthn"

const form = document.getElementById("sign-in") as HTMLFormElement | null
const text = messages(form)
let autofill: AbortController | null = null
// Set while an assertion is being checked or the page is on its way out, so autofill and the
// button never send two: the second answer would reach the app after the first had used it up.
let finishing = false
// The request has ended (expired, or finished elsewhere): offer the apps instead of a form that
// can only fail.
function ended(): void {
  autofill?.abort()
  const view = document.getElementById("ended")
  if (!view) return
  document.getElementById("request")?.setAttribute("hidden", "")
  view.hidden = false
  view.focus()
}

const failures: Record<string, string> = {
  "passkey-failed": "msgFailed",
  "device-passkey-needed": "msgDevicePasskey",
  "admin-needs-passkey": "msgAdminPasskey",
  "admin-needs-two-factor": "msgAdminTwoFactor",
  "code-failed": "msgCodeFailed",
  "password-failed": "msgPasswordFailed",
  "password-held": "msgPasswordHeld",
  busy: "msgBusy",
}

async function finish(credential: Credential | null): Promise<void> {
  if (!(credential instanceof PublicKeyCredential))
    throw new DOMException("no credential", "NotAllowedError")
  if (finishing) return
  finishing = true
  try {
    finishing = await send(credential)
  } catch (error) {
    finishing = false
    throw error
  }
}

/** Sends the assertion; true when the page is on its way to the app. */
async function send(credential: PublicKeyCredential): Promise<boolean> {
  const reply = await post("/login", { credential: assertionJson(credential) })
  await signal(reply.body)
  say("status", "")
  const to = redirect(reply)
  if (to) {
    window.location.assign(to)
    return true
  }
  failed(problem(reply))
  return false
}

function failed(kind: string): void {
  if (kind === "no-request") ended()
  else if (kind === "code-needed") askForCode()
  else say("error", text(failures[kind] ?? "msgError"))
}

/** The password was right: the code step takes the place of the username and password. */
function askForCode(): void {
  secondStep(true)
  document.querySelector<HTMLInputElement>("#code")?.focus()
}

/** Shows the code step, or goes back to the first step with the password cleared. */
function secondStep(shown: boolean): void {
  const user = document.getElementById("second-factor-user")
  if (user) user.textContent = field("username").trim()
  document.getElementById("first-step")?.toggleAttribute("hidden", shown)
  document.getElementById("second-factor")?.toggleAttribute("hidden", !shown)
  document.getElementById("lost-passkey")?.toggleAttribute("hidden", shown)
  for (const button of document.querySelectorAll("[data-provider]"))
    button.toggleAttribute("hidden", shown)
  alternatives()
}

/** Hides the other ways in when none of their buttons shows. */
function alternatives(): void {
  const view = document.getElementById("alternatives")
  const shown = [...(view?.querySelectorAll("button") ?? [])].some((button) => !button.hidden)
  view?.toggleAttribute("hidden", !shown)
}

function useAnotherAccount(): void {
  for (const id of ["password", "code"]) {
    const input = document.querySelector<HTMLInputElement>(`#${id}`)
    if (input) input.value = ""
  }
  say("error", "")
  secondStep(false)
  document.querySelector<HTMLInputElement>("#username")?.focus()
}

async function options(): Promise<PublicKeyCredentialRequestOptions | null> {
  const reply = await post("/login/options", {})
  if (!reply.ok) {
    say("error", text("msgError"))
    return null
  }
  return requestOptions(reply.body)
}

async function startAutofill(): Promise<void> {
  const available = await PublicKeyCredential.isConditionalMediationAvailable?.()
  if (!available) return
  const publicKey = await options()
  if (publicKey) await autofillWith(publicKey)
}

async function autofillWith(publicKey: PublicKeyCredentialRequestOptions): Promise<void> {
  autofill = new AbortController()
  // Nothing was asked of the user yet, so a failed offer stays quiet; the button shows the cause.
  const credential = await navigator.credentials
    .get({ publicKey, mediation: "conditional", signal: autofill.signal })
    .catch(() => null)
  if (credential) await finish(credential).catch(() => say("error", text("msgError")))
}

function field(id: string): string {
  return document.querySelector<HTMLInputElement>(`#${id}`)?.value ?? ""
}

function signInWithPassword(event: SubmitEvent): void {
  event.preventDefault()
  if (finishing) return
  const username = field("username").trim()
  const password = field("password")
  say("status", "")
  if (!username || !password) {
    say("error", text("msgPasswordMissing"))
    return
  }
  finishing = true
  say("error", "")
  void sendPassword(username, password)
}

async function sendPassword(username: string, password: string): Promise<void> {
  try {
    const reply = await post("/login/password", { username, password, code: typedCode() })
    finishing = leave(reply)
    if (!finishing) failed(problem(reply))
  } catch {
    finishing = false
    say("error", text("msgError"))
  }
}

/** The code typed, once the code field shows. */
function typedCode(): string | null {
  return document.getElementById("second-factor")?.hidden ? null : field("code").trim() || null
}

/** Goes to the app the reply names; true when the page is on its way out. */
function leave(reply: Reply): boolean {
  const to = redirect(reply)
  if (!to) return false
  autofill?.abort()
  window.location.assign(to)
  return true
}

function signInWithPasskey(): void {
  if (finishing) return
  autofill?.abort()
  void signInWithButton()
}

async function signInWithButton(): Promise<void> {
  say("error", "")
  say("status", text("msgWorking"))
  try {
    const publicKey = await options()
    if (!publicKey) return
    await finish(await navigator.credentials.get({ publicKey }))
  } catch (error) {
    say("status", "")
    say("error", text(cancelled(error) ? "msgCancelled" : "msgFailed"))
  }
}

// A page restored from the back-forward cache may show a request that has since ended.
window.addEventListener("pageshow", (event) => {
  if (event.persisted) window.location.reload()
})

if (form) {
  const expiresIn = Number(form.dataset.expiresIn)
  if (expiresIn >= 0) window.setTimeout(ended, expiresIn * 1000)
  // Upstream providers work without passkey support.
  upstreamButtons(
    () => {
      autofill?.abort()
      return {}
    },
    text,
    { "no-request": ended },
  )
  form.addEventListener("submit", signInWithPassword)
  document.getElementById("other-account")?.addEventListener("click", useAnotherAccount)
  const passkey = document.getElementById("passkey")
  if (!supported()) {
    passkey?.setAttribute("hidden", "")
    alternatives()
  } else {
    passkey?.addEventListener("click", signInWithPasskey)
    void startAutofill()
  }
}
