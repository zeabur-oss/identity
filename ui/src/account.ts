// Account page: sign in with a password or a passkey, then rename, add and remove passkeys, link and unlink GitHub or Google
// accounts, change or remove a password, and end sessions. Adding, linking and removing need a passkey confirmation from the
// last five minutes. The server says when one is due ("reauth-required"), and the page asks for
// it, then retries once.
import {
  assertionJson,
  cancelled,
  creationOptions,
  messages,
  post,
  problem,
  type Reply,
  registrationJson,
  requestOptions,
  signal,
  supported,
  write,
} from "./webauthn"
import { codeStep, entered, wireOtherAccount } from "./password"

const root = document.getElementById("account")
const text = messages(root)

const errors: Record<string, string> = {
  "passkey-failed": "msgFailed",
  "passkey-exists": "msgExists",
  "last-passkey": "msgLast",
  conflict: "msgChanged",
  "not-found": "msgGone",
  "signed-out": "msgSignedOut",
  "device-passkey-needed": "msgDevicePasskey",
  "last-credential": "msgLastCredential",
  "admin-needs-passkey": "msgAdminPasskey",
  "ceremony-expired": "msgExpired",
  "current-password-wrong": "msgPasswordWrong",
  "password-held": "msgPasswordHeld",
  "password-conflict": "msgPasswordConflict",
  busy: "msgBusy",
  "password-failed": "msgPasswordFailed",
  "code-failed": "msgCodeFailed",
  "admin-needs-two-factor": "msgAdminTwoFactor",
}

const weaknesses: Record<string, string> = {
  "too-short": "msgTooShort",
  "too-long": "msgTooLong",
  common: "msgCommon",
  context: "msgContext",
}

/** The message for a problem code, or the generic one. */
const explain = (code: string): string => text(errors[code] ?? "msgError")

/** Where a task reports progress and failure: the page header, or a passkey's row. */
type Place = { status: HTMLElement | null; error: HTMLElement | null }

const header: Place = {
  status: document.getElementById("status"),
  error: document.getElementById("error"),
}

/** Problems that mean the page shows a stale list: reload it from the server, then explain. */
const stale = new Set(["last-passkey", "conflict", "not-found", "password-conflict"])

function fail(place: Place, message: string): void {
  write(place.status, "")
  write(place.error, message)
}

function refresh(code: string, passkey: string): void {
  if (code === "not-found" && !passkey) return window.location.reload()
  const notice = new URLSearchParams({ notice: code })
  if (passkey) notice.set("passkey", passkey)
  window.location.hash = notice.toString()
  window.location.reload()
}

/** After `refresh`: shows its message on the passkey's row if it is still listed, else at the top. */
function showNotice(): void {
  const notice = new URLSearchParams(window.location.hash.slice(1))
  const code = notice.get("notice")
  if (!code || !stale.has(code)) return
  window.history.replaceState(null, "", window.location.pathname + window.location.search)
  const name = notice.get("passkey")
  const row = [...document.querySelectorAll<HTMLElement>("[data-passkey]")].find(
    (item) => item.dataset.passkey === name,
  )
  write((row ? rowPlace(row) : header).error, explain(code))
}

/** Notices for a change that worked, set in the hash before a reload. */
const done: Record<string, string> = {
  "#notice=linked": "msgLinked",
  "#notice=password-changed": "msgPasswordChanged",
  "#notice=password-removed": "msgPasswordRemoved",
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

async function assertion(
  path: string,
  extra: Record<string, unknown>,
): Promise<PublicKeyCredential> {
  const started = await post(path, extra)
  if (!started.ok) throw started
  const credential = await navigator.credentials.get({ publicKey: requestOptions(started.body) })
  if (!(credential instanceof PublicKeyCredential))
    throw new DOMException("no credential", "NotAllowedError")
  return credential
}

async function reauthenticate(place: Place): Promise<Reply> {
  write(place.status, text("msgConfirm"))
  const credential = await assertion("/account/reauth/options", {})
  return post("/account/reauth", { credential: assertionJson(credential) })
}

/** Runs `action`; if the server wants a fresh confirmation, gets one and runs it again. */
async function fresh(place: Place, action: () => Promise<Reply>): Promise<Reply> {
  const first = await action()
  if (problem(first) !== "reauth-required") return first
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
  const code = problem(reply)
  if (stale.has(code)) refresh(code, passkey)
  else if (code === "password-weak")
    fail(place, text(weaknesses[String(reply.body.weakness)] ?? "msgCommon"))
  else fail(place, explain(code))
}

function signInWithPassword(event: SubmitEvent): void {
  event.preventDefault()
  const { username, password, code } = entered()
  if (!username || !password) return fail(header, text("msgPasswordMissing"))
  run(async () => {
    const reply = await post("/account/session/password", { username, password, code })
    if (problem(reply) !== "code-needed") return reply
    write(header.status, "")
    codeStep(true)
    return null
  })
}

function signIn(): void {
  run(async () => {
    const credential = await assertion("/account/session/options", {})
    return post("/account/session", { credential: assertionJson(credential) })
  })
}

function addPasskey(event: SubmitEvent): void {
  event.preventDefault()
  const label = document.querySelector<HTMLInputElement>("#add-label")?.value.trim()
  run(async () => {
    const started = await fresh(header, () => post("/account/passkeys/options", {}))
    if (!started.ok) return started
    write(header.status, text("msgWorking"))
    const credential = await navigator.credentials.create({
      publicKey: creationOptions(started.body),
    })
    if (!(credential instanceof PublicKeyCredential))
      throw new DOMException("no credential", "NotAllowedError")
    return post("/account/passkeys", {
      credential: registrationJson(credential),
      label: label || null,
    })
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
): void {
  const dialog = item.querySelector<HTMLDialogElement>(`dialog[data-${name}]`)
  if (!dialog) return
  item.querySelector(`[data-opens=${name}]`)?.addEventListener("click", () => {
    dialog.returnValue = ""
    dialog.showModal()
  })
  dialog.querySelector("[data-close]")?.addEventListener("click", () => dialog.close())
  dialog.addEventListener("close", () => {
    if (dialog.returnValue === "confirm") confirmed(dialog)
  })
}

/** Wires a row's remove confirmation. `passkey` names the row's passkey, if any. */
function wireRemove(item: HTMLElement, path: string, name: string, passkey: string): void {
  wireDialog(item, "confirm", () => {
    const place = rowPlace(item)
    run(() => fresh(place, () => post(path, { name })), place, passkey)
  })
}

function wirePasskey(item: HTMLElement): void {
  const name = item.dataset.passkey ?? ""
  wireRemove(item, "/account/passkeys/remove", name, name)
  wireDialog(item, "rename", (dialog) => {
    const label = dialog.querySelector("input")?.value.trim() ?? ""
    if (label) run(() => post("/account/passkeys/rename", { name, label }), rowPlace(item), name)
  })
}

/** Starts linking: after a fresh confirmation, the server answers with the provider's URL. */
function link(provider: string): void {
  run(async () => {
    const reply = await fresh(header, () => post("/account/links/start", { provider }))
    if (!reply.ok || typeof reply.body.redirect_to !== "string") return reply
    window.location.assign(reply.body.redirect_to)
    return null
  })
}

/** Sends a password change or removal; on success, the reload shows `notice`. */
async function password(
  path: string,
  body: Record<string, string>,
  notice: string,
): Promise<Reply> {
  const reply = await post(path, body)
  if (reply.ok) window.location.hash = `notice=${notice}`
  return reply
}

function wirePassword(section: HTMLElement): void {
  const place = rowPlace(section)
  const form = section.querySelector<HTMLFormElement>("#password-change")
  form?.addEventListener("submit", (event) => {
    event.preventDefault()
    const field = (name: string) =>
      form.querySelector<HTMLInputElement>(`[name=${name}]`)?.value ?? ""
    const current = field("current")
    const next = field("new")
    if (next.length < 15) return fail(place, text("msgTooShort"))
    run(() => password("/account/password", { current, new: next }, "password-changed"), place)
  })
  wireDialog(section, "confirm", (dialog) => {
    const current = dialog.querySelector("input")?.value ?? ""
    if (current)
      run(() => password("/account/password/remove", { current }, "password-removed"), place)
  })
}

function localizeDates(): void {
  const format = new Intl.DateTimeFormat(root?.dataset.lang, { dateStyle: "medium" })
  for (const time of document.querySelectorAll<HTMLTimeElement>("time[data-format]")) {
    const date = new Date(time.dateTime)
    if (!Number.isNaN(date.getTime()))
      time.textContent = (time.dataset.format ?? "%date%").replace("%date%", format.format(date))
  }
}

if (root) {
  localizeDates()
  document
    .getElementById("sign-out")
    ?.addEventListener("click", () => run(() => post("/account/sign-out", {})))
  document.getElementById("sign-out-others")?.addEventListener("click", () => {
    run(() => post("/account/sessions/revoke-others", {}))
  })
  const passwordSection = document.getElementById("password")
  if (passwordSection) wirePassword(passwordSection)
  for (const item of document.querySelectorAll<HTMLElement>("[data-session]")) {
    item.querySelector("[data-action=revoke]")?.addEventListener("click", () => {
      run(() => post("/account/sessions/revoke", { name: item.dataset.session ?? "" }))
    })
  }
  document.getElementById("sign-in")?.addEventListener("submit", signInWithPassword)
  wireOtherAccount(() => {
    fail(header, "")
    codeStep(false)
  })
  const signInButton = document.getElementById("account-sign-in")
  const add = document.getElementById("add") as HTMLFormElement | null
  if (!supported()) {
    document.getElementById("unsupported")?.removeAttribute("hidden")
    document.getElementById("passkey-sign-in")?.setAttribute("hidden", "")
    if (add) add.hidden = true
  } else {
    signInButton?.addEventListener("click", signIn)
    add?.addEventListener("submit", addPasskey)
    for (const item of document.querySelectorAll<HTMLElement>("[data-passkey]")) wirePasskey(item)
    for (const item of document.querySelectorAll<HTMLElement>("[data-linked]"))
      wireRemove(item, "/account/links/remove", item.dataset.linked ?? "", "")
    for (const button of document.querySelectorAll<HTMLButtonElement>("button[data-link]"))
      button.addEventListener("click", () => link(button.dataset.link ?? ""))
    if (window.location.hash === "#add") document.getElementById("add-label")?.focus()
  }
  showNotice()
  showDone()
}
