// Account page: sign in with a password or a passkey, then rename, add and remove passkeys, link and unlink GitHub or Google
// accounts, add, change or remove a password, replace the authenticator or its recovery codes, and end sessions. Adding,
// linking and removing need a passkey confirmation from the last five minutes. The server says when one is due (next step "reauth"), and the page asks for
// it, then retries once.
import {
  assertionJson,
  cancelled,
  creationOptions,
  explain,
  messages,
  next,
  call,
  redirect,
  type Reply,
  registrationJson,
  requestOptions,
  signal,
  stale,
  supported,
  write,
} from "./webauthn"
import { codeStep, entered, longEnough, wireOtherAccount } from "./password"
import { showEnrolment, showRecovery, totpAnswer } from "./totp"
import type { AccountRecoveryCodes, PasswordSetupOptions, TotpEnrolment } from "./contract"

const root = document.getElementById("account")
const text = messages(root)

/** Where a task reports progress and failure: the page header, or a passkey's row. */
type Place = { status: HTMLElement | null; error: HTMLElement | null }

const header: Place = {
  status: document.getElementById("status"),
  error: document.getElementById("error"),
}

function fail(place: Place, message: string): void {
  write(place.status, "")
  write(place.error, message)
}

type Notice = { message: string; passkey: string }

/**
 * Reloads a list that changed in the meantime; the reloaded page shows `message`. The message
 * rides in the history entry, which survives the reload and which no link can set.
 */
function refresh(message: string, passkey: string): void {
  window.history.replaceState({ notice: { message, passkey } satisfies Notice }, "")
  window.location.reload()
}

/** After `refresh`: shows its message on the passkey's row if it is still listed, else at the top. */
function showNotice(): void {
  const notice = (window.history.state as { notice?: Notice } | null)?.notice
  if (!notice) return
  window.history.replaceState(null, "")
  const row = [...document.querySelectorAll<HTMLElement>("[data-passkey]")].find(
    (item) => item.dataset.passkey === notice.passkey,
  )
  write((row ? rowPlace(row) : header).error, notice.message)
}

/** Notices for a change that worked, set in the hash before a reload. */
const done: Record<string, string> = {
  "#notice=linked": "msgLinked",
  "#notice=password-changed": "msgPasswordChanged",
  "#notice=password-removed": "msgPasswordRemoved",
  "#notice=password-added": "msgPasswordAdded",
  "#notice=authenticator-replaced": "msgAuthenticatorReplaced",
  "#notice=recovery-regenerated": "msgRecoveryRegenerated",
}

/** After a reload that follows a change that worked, or after the provider sends the person back. */
function showDone(): void {
  const key = done[window.location.hash]
  if (!key) return
  window.history.replaceState(null, "", window.location.pathname + window.location.search)
  write(header.status, text(key))
}

function rowPlace(item: HTMLElement): Place {
  return { status: item.querySelector("[data-status]"), error: item.querySelector("[data-error]") }
}

async function assertion(route: "sessionOptions" | "reauthOptions"): Promise<PublicKeyCredential> {
  const started = await call(route, null)
  if (!started.ok) throw started
  const credential = await navigator.credentials.get({ publicKey: requestOptions(started.body) })
  if (!(credential instanceof PublicKeyCredential))
    throw new DOMException("no credential", "NotAllowedError")
  return credential
}

async function reauthenticate(place: Place): Promise<Reply> {
  write(place.status, text("msgConfirm"))
  const credential = await assertion("reauthOptions")
  return call("reauth", { credential: assertionJson(credential) })
}

/** Runs `action`; if the server wants a fresh confirmation, gets one and runs it again. */
async function fresh(place: Place, action: () => Promise<Reply>): Promise<Reply> {
  const first = await action()
  if (next(first) !== "reauth") return first
  const confirmed = await reauthenticate(place)
  return confirmed.ok ? action() : confirmed
}

/** Set while a task runs, so a second press does not send the same change twice. */
let running = false

const isReply = (value: unknown): value is Reply =>
  typeof value === "object" && value !== null && "status" in value

/**
 * Wraps a click or submit handler: status while working, then reload or explain at `place`.
 * `passkey` names the row's passkey, so a stale-list refusal can point back at it.
 */
function run(task: () => Promise<Reply | null>, place: Place = header, passkey = ""): void {
  if (running) return
  running = true
  for (const p of new Set([header, place])) write(p.error, "")
  write(place.status, text("msgWorking"))
  task()
    .then((reply) => reply && settle(reply, place, passkey))
    .catch((error: unknown) => {
      if (isReply(error)) refused(error, place, passkey)
      else fail(place, text(cancelled(error) ? "msgCancelled" : "msgFailed"))
    })
    .finally(() => {
      running = false
    })
}

/** A finished task: reload to show the change, or explain why there is none. */
async function settle(reply: Reply, place: Place, passkey: string): Promise<void> {
  if (!reply.ok) return refused(reply, place, passkey)
  await signal(reply.body)
  window.location.reload()
}

function refused(reply: Reply, place: Place, passkey: string): void {
  if (stale(reply)) refresh(explain(reply, text), passkey)
  else fail(place, explain(reply, text))
}

function signInWithPassword(event: SubmitEvent): void {
  event.preventDefault()
  const { username, password, code } = entered()
  if (!username || !password) return fail(header, text("msgPasswordMissing"))
  run(async () => {
    const reply = await call("passwordSignIn", { username, password, code })
    if (next(reply) !== "code") return reply
    write(header.status, "")
    codeStep(true)
    return null
  })
}

function signIn(): void {
  run(async () => {
    const credential = await assertion("sessionOptions")
    return call("signIn", { credential: assertionJson(credential) })
  })
}

function addPasskey(label: string): void {
  run(async () => {
    const started = await fresh(header, () => call("addPasskeyOptions", null))
    if (!started.ok) return started
    write(header.status, text("msgWorking"))
    const credential = await navigator.credentials.create({
      publicKey: creationOptions(started.body),
    })
    if (!(credential instanceof PublicKeyCredential))
      throw new DOMException("no credential", "NotAllowedError")
    return call("addPasskey", { credential: registrationJson(credential), label: label || null })
  })
}

/**
 * Opens a row's dialog (`dialog[data-<name>]`) from its `data-opens` button. `confirmed` runs when
 * the dialog closes through its confirm button; cancel, Escape and the backdrop leave things as
 * they were.
 */
function wireDialog(
  item: HTMLElement,
  name: string,
  confirmed: (dialog: HTMLDialogElement) => void,
  open: (dialog: HTMLDialogElement) => void = (dialog) => dialog.showModal(),
): void {
  const dialog = item.querySelector<HTMLDialogElement>(`dialog[data-${name}]`)
  const opener = item.querySelector(`[data-opens=${name}]`)
  if (!dialog) return
  opener?.addEventListener("click", () => {
    dialog.returnValue = ""
    open(dialog)
  })
  dialog.querySelector("[data-close]")?.addEventListener("click", () => dialog.close())
  dialog.addEventListener("close", () => {
    if (dialog.returnValue === "confirm") confirmed(dialog)
  })
}

/** Wires a row's remove confirmation. `passkey` names the row's passkey, if any. */
function wireRemove(item: HTMLElement, remove: () => Promise<Reply>, passkey: string): void {
  wireDialog(item, "confirm", () => {
    const place = rowPlace(item)
    run(() => fresh(place, remove), place, passkey)
  })
}

function wirePasskey(item: HTMLElement): void {
  const name = item.dataset.passkey ?? ""
  wireRemove(item, () => call("removePasskey", null, { name }), name)
  wireDialog(item, "rename", (dialog) => {
    const label = dialog.querySelector("input")?.value.trim() ?? ""
    if (label) run(() => call("renamePasskey", { label }, { name }), rowPlace(item), name)
  })
}

/** Starts linking: after a fresh confirmation, the server answers with the provider's URL. */
function link(button: HTMLElement): void {
  const provider = button.dataset.link ?? ""
  run(async () => {
    const reply = await fresh(header, () => call("link", { provider }))
    const to = redirect(reply)
    if (!to) return reply
    window.location.assign(to)
    return null
  })
}

/** Sends a password change or removal; on success, the reload shows `notice`. */
async function password(send: () => Promise<Reply>, notice: string): Promise<Reply> {
  const reply = await send()
  if (reply.ok) window.location.hash = `notice=${notice}`
  return reply
}

/**
 * After a change that worked: shows the recovery codes it made, if any, until the person says they
 * saved them; the reload then shows `notice`.
 */
function keepCodes(reply: Reply, notice: string, place: Place): Reply | null {
  if (!reply.ok) return reply
  window.location.hash = `notice=${notice}`
  const codes = (reply.body as AccountRecoveryCodes).recovery_codes
  if (!codes) return reply
  write(place.status, "")
  showRecovery(codes)
  document.getElementById("recovery")?.focus()
  return null
}

/** Sends a change that may make recovery codes, confirmed with a passkey when the server asks. */
function sendForCodes(place: Place, send: () => Promise<Reply>, notice: string): void {
  run(async () => keepCodes(await fresh(place, send), notice, place), place)
}

/** Runs `options` and opens `dialog` with what it answers, or explains at `place` why not. */
function openWith(
  dialog: HTMLDialogElement,
  place: Place,
  options: () => Promise<Reply>,
  shown: (body: unknown) => void,
): void {
  run(async () => {
    const reply = await options()
    if (!reply.ok) return reply
    shown(reply.body)
    write(place.status, "")
    dialog.showModal()
    return null
  }, place)
}

/** The current password and code typed in `dialog`, or nulls to confirm with a passkey. */
function confirmation(dialog: HTMLDialogElement): { current: string | null; code: string | null } {
  const field = (name: string) =>
    dialog.querySelector<HTMLInputElement>(`[name=${name}]`)?.value ?? ""
  return { current: field("current") || null, code: field("code").trim() || null }
}

/** Adding a password: after a passkey confirmation, with an authenticator when one is needed. */
function wireAdd(section: HTMLElement): void {
  const place = rowPlace(section)
  let sealed: string | null = null
  wireDialog(
    section,
    "add-password",
    (dialog) => {
      const chosen = dialog.querySelector<HTMLInputElement>("[name=new]")
      if (!longEnough(chosen)) return fail(place, text("msgTooShort"))
      const body = { password: chosen.value, totp: totpAnswer(sealed) }
      sendForCodes(place, () => call("addPassword", body), "password-added")
    },
    (dialog) =>
      openWith(
        dialog,
        place,
        () => fresh(place, () => call("addPasswordOptions", null)),
        (body) => {
          const { totp } = body as PasswordSetupOptions
          sealed = totp ? showEnrolment(totp) : null
        },
      ),
  )
}

/** Replacing the authenticator or its recovery codes, confirmed in the dialog or with a passkey. */
function wireAuthenticator(section: HTMLElement): void {
  const place = rowPlace(section)
  let sealed: string | null = null
  wireDialog(
    section,
    "authenticator",
    (dialog) => {
      const totp = totpAnswer(sealed)
      if (!totp) return
      const body = { ...confirmation(dialog), totp }
      sendForCodes(place, () => call("replaceAuthenticator", body), "authenticator-replaced")
    },
    (dialog) =>
      openWith(
        dialog,
        place,
        () => call("authenticatorOptions", null),
        (body) => {
          sealed = showEnrolment(body as TotpEnrolment)
        },
      ),
  )
  wireDialog(section, "recovery", (dialog) => {
    const body = confirmation(dialog)
    sendForCodes(place, () => call("regenerateRecoveryCodes", body), "recovery-regenerated")
  })
}

function wirePassword(section: HTMLElement): void {
  wireAdd(section)
  wireAuthenticator(section)
  const place = rowPlace(section)
  wireDialog(section, "change", (dialog) => {
    const current = dialog.querySelector<HTMLInputElement>("[name=current]")?.value
    const chosen = dialog.querySelector<HTMLInputElement>("[name=new]")
    if (!current) return
    if (!longEnough(chosen)) return fail(place, text("msgTooShort"))
    const body = { current, new: chosen.value }
    run(() => password(() => call("changePassword", body), "password-changed"), place)
  })
  wireDialog(section, "confirm", (dialog) => {
    const current = dialog.querySelector("input")?.value ?? ""
    if (current)
      run(() => password(() => call("removePassword", { current }), "password-removed"), place)
  })
}

function localizeDates(): void {
  const format = new Intl.DateTimeFormat(root?.dataset.lang, { dateStyle: "medium" })
  for (const time of document.querySelectorAll<HTMLTimeElement>("time[datetime]")) {
    const date = new Date(time.dateTime)
    if (!Number.isNaN(date.getTime())) time.textContent = format.format(date)
  }
}

if (root) {
  localizeDates()
  document
    .getElementById("sign-out")
    ?.addEventListener("click", () => run(() => call("signOut", null)))
  document
    .getElementById("sign-out-others")
    ?.addEventListener("click", () => run(() => call("revokeOtherSessions", null)))
  const passwordSection = document.getElementById("password")
  if (passwordSection) wirePassword(passwordSection)
  document
    .getElementById("recovery-saved")
    ?.addEventListener("click", () => window.location.reload())
  for (const item of document.querySelectorAll<HTMLElement>("[data-session]")) {
    const button = item.querySelector("[data-action=revoke]")
    button?.addEventListener("click", () => {
      run(() => call("revokeSession", null, { name: item.dataset.session ?? "" }))
    })
  }
  document.getElementById("sign-in")?.addEventListener("submit", signInWithPassword)
  wireOtherAccount(() => {
    fail(header, "")
    codeStep(false)
  })
  const signInButton = document.getElementById("account-sign-in")
  const passkeys = document.getElementById("passkeys")
  if (!supported()) {
    document.getElementById("unsupported")?.removeAttribute("hidden")
    document.getElementById("passkey-sign-in")?.setAttribute("hidden", "")
    document.getElementById("add")?.setAttribute("hidden", "")
  } else {
    signInButton?.addEventListener("click", signIn)
    if (passkeys)
      wireDialog(passkeys, "add", (dialog) => {
        addPasskey(dialog.querySelector("input")?.value.trim() ?? "")
      })
    for (const item of document.querySelectorAll<HTMLElement>("[data-passkey]")) wirePasskey(item)
    for (const item of document.querySelectorAll<HTMLElement>("[data-linked]"))
      wireRemove(item, () => call("unlink", null, { name: item.dataset.linked ?? "" }), "")
    for (const button of document.querySelectorAll<HTMLButtonElement>("button[data-link]"))
      button.addEventListener("click", () => link(button))
    if (window.location.hash === "#add") document.getElementById("add")?.click()
  }
  showNotice()
  showDone()
}
