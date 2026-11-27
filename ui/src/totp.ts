// The authenticator steps that the setup and account pages share (templates/totp.html): the QR
// code and key of a new authenticator, the code typed for it, and the recovery codes shown once.
import type { TotpEnrolment } from "./contract"

/** Shows `offered` in the authenticator step. Returns its sealed secret, to send back. */
export function showEnrolment(offered: TotpEnrolment): string {
  drawQr(offered.qr.size, offered.qr.path)
  const secret = document.getElementById("totp-secret")
  if (secret) secret.textContent = offered.secret_display
  const code = document.querySelector<HTMLInputElement>("#totp-code")
  if (code) code.value = ""
  document.getElementById("totp")?.removeAttribute("hidden")
  return offered.sealed
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

/** The sealed secret with the code typed for it, or null when no authenticator was offered. */
export function totpAnswer(sealed: string | null): { sealed: string; code: string } | null {
  if (!sealed) return null
  const code = document.querySelector<HTMLInputElement>("#totp-code")?.value.trim() ?? ""
  return { sealed, code }
}

/** Lists `codes` in the recovery step and shows it. */
export function showRecovery(codes: string[]): void {
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
