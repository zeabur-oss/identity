// The password sign-in steps that the sign-in and account pages share (templates/password.html):
// username and password, then the code once the server asks for it.

function field(id: string): string {
  return document.querySelector<HTMLInputElement>(`#${id}`)?.value ?? ""
}

/** What the person typed. `code` is set only once the code step shows. */
export function entered(): { username: string; password: string; code: string | null } {
  const codeShown = !document.getElementById("second-factor")?.hidden
  return {
    username: field("username").trim(),
    password: field("password"),
    code: codeShown ? field("code").trim() || null : null,
  }
}

/** Shows the code step in place of the username and password, or the first step again. */
export function codeStep(shown: boolean): void {
  const user = document.getElementById("second-factor-user")
  if (user) user.textContent = field("username").trim()
  document.getElementById("first-step")?.toggleAttribute("hidden", shown)
  document.getElementById("second-factor")?.toggleAttribute("hidden", !shown)
  if (shown) document.querySelector<HTMLInputElement>("#code")?.focus()
}

/** "Use another account": clears the password and code, then goes back to the first step. */
export function wireOtherAccount(back: () => void): void {
  document.getElementById("other-account")?.addEventListener("click", () => {
    for (const id of ["password", "code"]) {
      const input = document.querySelector<HTMLInputElement>(`#${id}`)
      if (input) input.value = ""
    }
    back()
    document.querySelector<HTMLInputElement>("#username")?.focus()
  })
}
