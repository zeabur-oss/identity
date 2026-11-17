// Sign-in page: username and password, passkey autofill (conditional mediation) on the username
// field, and a passkey button.
import {
  assertionJson,
  cancelled,
  messages,
  post,
  problem,
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
  else say("error", text(failures[kind] ?? "msgError"))
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
  try {
    const credential = await navigator.credentials.get({
      publicKey,
      mediation: "conditional",
      signal: autofill.signal,
    })
    await finish(credential)
  } catch (error) {
    // Aborted when the user presses the button instead; other errors surface on the next attempt.
    if (!cancelled(error)) say("error", text("msgError"))
  }
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
    const reply = await post("/login/password", { username, password })
    const to = redirect(reply)
    if (to) {
      autofill?.abort()
      window.location.assign(to)
      return
    }
    finishing = false
    failed(problem(reply))
  } catch {
    finishing = false
    say("error", text("msgError"))
  }
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
  const passkey = document.getElementById("passkey")
  if (!supported()) passkey?.setAttribute("hidden", "")
  else {
    passkey?.addEventListener("click", signInWithPasskey)
    void startAutofill()
  }
}
