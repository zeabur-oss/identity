// Account page: sign in, then rename, add and remove passkeys, link and unlink GitHub or Google
// accounts, and end sessions. Adding, linking and removing need a passkey confirmation from the
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

const root = document.getElementById("account")
const text = messages(root)
const csrf = text("csrf")

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
const stale = new Set(["last-passkey", "conflict", "not-found"])

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

/** After the provider sends the person back with a new link. */
function showLinked(): void {
  if (window.location.hash !== "#notice=linked") return
  window.history.replaceState(null, "", window.location.pathname + window.location.search)
  write(header.status, text("msgLinked"))
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
  const credential = await assertion("/account/reauth/options", { csrf })
  return post("/account/reauth", { csrf, credential: assertionJson(credential) })
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
  else fail(place, explain(code))
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
    const started = await fresh(header, () => post("/account/passkeys/options", { csrf }))
    if (!started.ok) return started
    write(header.status, text("msgWorking"))
    const credential = await navigator.credentials.create({
      publicKey: creationOptions(started.body),
    })
    if (!(credential instanceof PublicKeyCredential))
      throw new DOMException("no credential", "NotAllowedError")
    return post("/account/passkeys", {
      csrf,
      credential: registrationJson(credential),
      label: label || null,
    })
  })
}

/** A row's parts, each with the control that takes focus when it opens. */
const parts = {
  actions: { selector: "[data-actions]", focus: null },
  rename: { selector: "[data-rename]", focus: "input" },
  confirm: { selector: "[data-confirm]", focus: "[data-action=confirm-remove]" },
} as const

/** Shows one part of a row and hides the others. */
function show(item: HTMLElement, shown: keyof typeof parts): void {
  for (const [name, { selector }] of Object.entries(parts)) {
    const element = item.querySelector<HTMLElement>(selector)
    if (element) element.hidden = name !== shown
  }
  const { selector, focus } = parts[shown]
  if (focus) item.querySelector<HTMLElement>(`${selector} ${focus}`)?.focus()
}

/** Wires a row's remove, confirm and cancel buttons. `passkey` names the row's passkey, if any. */
function wireRemove(item: HTMLElement, path: string, name: string, passkey: string): void {
  item.querySelector("[data-action=remove]")?.addEventListener("click", () => show(item, "confirm"))
  for (const cancel of item.querySelectorAll("[data-action=cancel]")) {
    cancel.addEventListener("click", () => {
      write(rowPlace(item).error, "")
      show(item, "actions")
    })
  }
  item.querySelector("[data-action=confirm-remove]")?.addEventListener("click", () => {
    const place = rowPlace(item)
    run(() => fresh(place, () => post(path, { csrf, name })), place, passkey)
  })
}

function wirePasskey(item: HTMLElement): void {
  const name = item.dataset.passkey ?? ""
  item.querySelector("[data-action=rename]")?.addEventListener("click", () => show(item, "rename"))
  wireRemove(item, "/account/passkeys/remove", name, name)
  item.querySelector<HTMLFormElement>("[data-rename]")?.addEventListener("submit", (event) => {
    event.preventDefault()
    const label = item.querySelector<HTMLInputElement>("[data-rename] input")?.value.trim() ?? ""
    if (label)
      run(() => post("/account/passkeys/rename", { csrf, name, label }), rowPlace(item), name)
  })
}

/** Starts linking: after a fresh confirmation, the server answers with the provider's URL. */
function link(provider: string): void {
  run(async () => {
    const reply = await fresh(header, () => post("/account/links/start", { csrf, provider }))
    if (!reply.ok || typeof reply.body.redirect_to !== "string") return reply
    window.location.assign(reply.body.redirect_to)
    return null
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
    ?.addEventListener("click", () => run(() => post("/account/sign-out", { csrf })))
  document.getElementById("sign-out-others")?.addEventListener("click", () => {
    run(() => post("/account/sessions/revoke-others", { csrf }))
  })
  for (const item of document.querySelectorAll<HTMLElement>("[data-session]")) {
    item.querySelector("[data-action=revoke]")?.addEventListener("click", () => {
      run(() => post("/account/sessions/revoke", { csrf, name: item.dataset.session ?? "" }))
    })
  }
  const signInButton = document.getElementById("account-sign-in")
  const add = document.getElementById("add") as HTMLFormElement | null
  if (!supported()) {
    document.getElementById("unsupported")?.removeAttribute("hidden")
    if (signInButton) signInButton.hidden = true
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
  showLinked()
}
