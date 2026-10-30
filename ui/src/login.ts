// Sign-in page: passkey autofill (conditional mediation) plus an explicit button.
import {
  assertionJson,
  cancelled,
  post,
  problem,
  requestOptions,
  say,
  signal,
  supported,
  upstreamButtons,
} from "./webauthn"

const form = document.getElementById("sign-in") as HTMLFormElement | null
const messages = form?.dataset ?? {}
let autofill: AbortController | null = null
// Set while an assertion is being checked or the page is on its way out, so autofill and the
// button never send two: the second answer would reach the app after the first had used it up.
let finishing = false
const usernameField = document.getElementById("username-field")
const useUsername = document.getElementById("use-username")

// Without a login hint the field is only where the browser lists passkeys, so it stays folded
// behind "Use a username" while the browser can offer them there.
function fold(folded: boolean): void {
  if (!usernameField?.hasAttribute("data-collapsible") || !useUsername) return
  usernameField.hidden = folded
  useUsername.hidden = !folded
}

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

const failures: Record<string, string | undefined> = {
  "passkey-failed": messages.msgFailed,
  "device-passkey-needed": messages.msgDevicePasskey,
}

async function finish(credential: Credential | null): Promise<void> {
  if (!(credential instanceof PublicKeyCredential))
    throw new DOMException("no credential", "NotAllowedError")
  if (finishing) return
  finishing = true
  const reply = await post("/login", { credential: assertionJson(credential) }).catch(
    (error: unknown) => {
      finishing = false
      throw error
    },
  )
  await signal(reply.body)
  if (reply.ok && typeof reply.body.redirect_to === "string") {
    say("status", "")
    window.location.assign(reply.body.redirect_to)
    return
  }
  finishing = false
  say("status", "")
  const kind = problem(reply)
  if (kind === "no-request") ended()
  else say("error", failures[kind] ?? messages.msgError ?? "")
}

async function options(): Promise<PublicKeyCredentialRequestOptions | null> {
  const reply = await post("/login/options", {})
  if (!reply.ok) {
    say("error", messages.msgError ?? "")
    return null
  }
  return requestOptions(reply.body)
}

async function startAutofill(): Promise<void> {
  const available = await PublicKeyCredential.isConditionalMediationAvailable?.()
  if (!available) {
    fold(false)
    return
  }
  const publicKey = await options()
  if (!publicKey) return
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
    if (!cancelled(error)) say("error", messages.msgError ?? "")
  }
}

async function signIn(event: SubmitEvent): Promise<void> {
  event.preventDefault()
  if (finishing) return
  autofill?.abort()
  say("error", "")
  say("status", messages.msgWorking ?? "")
  try {
    const publicKey = await options()
    if (!publicKey) return
    await finish(await navigator.credentials.get({ publicKey }))
  } catch (error) {
    say("status", "")
    say("error", cancelled(error) ? (messages.msgCancelled ?? "") : (messages.msgFailed ?? ""))
  }
}

// A page restored from the back-forward cache may show a request that has since ended.
window.addEventListener("pageshow", (event) => {
  if (event.persisted) window.location.reload()
})

if (form) {
  const expiresIn = Number(messages.expiresIn)
  if (expiresIn >= 0) window.setTimeout(ended, expiresIn * 1000)
  // Upstream providers work without passkey support.
  upstreamButtons(
    () => {
      autofill?.abort()
      return {}
    },
    messages,
    { "no-request": ended },
  )
  if (!supported()) {
    document.getElementById("unsupported")?.removeAttribute("hidden")
    form.hidden = true
  } else {
    form.addEventListener("submit", (event) => void signIn(event))
    useUsername?.addEventListener("click", () => {
      fold(false)
      document.getElementById("username")?.focus()
    })
    fold(typeof PublicKeyCredential.isConditionalMediationAvailable === "function")
    void startAutofill()
  }
}
