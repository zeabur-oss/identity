// Writes the design system's component classes as askama macros, for the templates to call as
// `ds::<macro>(…)`. scripts/build-ui.sh runs it; CI fails when the committed output differs.
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

import {
  alertDescriptionVariants,
  alertTitleVariants,
  alertVariants,
} from "@zeabur/design-system/variants/alert"
import { badgeVariants } from "@zeabur/design-system/variants/badge"
import { buttonVariants } from "@zeabur/design-system/variants/button"
import {
  cardContentVariants,
  cardDescriptionVariants,
  cardHeaderVariants,
  cardTitleVariants,
  cardVariants,
} from "@zeabur/design-system/variants/card"
import {
  dialogBackdropVariants,
  dialogBodyVariants,
  dialogContentVariants,
  dialogDescriptionVariants,
  dialogFooterVariants,
  dialogHeaderVariants,
  dialogTitleVariants,
} from "@zeabur/design-system/variants/dialog"
import {
  fieldDescriptionVariants,
  fieldErrorVariants,
  fieldLabelVariants,
  fieldVariants,
} from "@zeabur/design-system/variants/field"
import { inputVariants } from "@zeabur/design-system/variants/input"
import { separatorVariants } from "@zeabur/design-system/variants/separator"
import { cn } from "cn"

type Props = Record<string, string>

type Macro = {
  classes: (props: Props) => string
  /** Each parameter of the macro, with the values the templates pass. */
  params?: Record<string, string[]>
  /** Identity's own classes, merged over the design system's. */
  identity?: string
}

/** `classes` for a pseudo-element: each class behind `variant:` (`backdrop:bg-overlay`). */
const on = (variant: string, classes: string): string =>
  classes
    .split(" ")
    .map((name) => `${variant}:${name}`)
    .join(" ")

// The sign-in card has more padding and a larger, centred heading than the design system's card.
// A dialog is a native <dialog>, centred by the browser's margins instead of the design system's
// translate, with the backdrop on its ::backdrop.
const macros: Record<string, Macro> = {
  button: {
    classes: buttonVariants,
    params: {
      variant: ["primary", "secondary", "destructive", "secondary-destructive"],
      size: ["lg", "sm"],
    },
  },
  input: { classes: () => inputVariants({ size: "lg" }) },
  card: { classes: () => cardVariants(), identity: "gap-5 py-6 shadow-xs" },
  card_header: { classes: () => cardHeaderVariants(), identity: "gap-1 px-6 text-center sm:px-7" },
  card_title: {
    classes: () => cardTitleVariants(),
    identity: "text-xl leading-7 font-semibold tracking-[-0.01em]",
  },
  card_description: { classes: () => cardDescriptionVariants(), identity: "text-pretty" },
  card_content: { classes: () => cardContentVariants(), identity: "px-6 sm:px-7" },
  alert: { classes: alertVariants, params: { variant: ["default", "warn", "destructive"] } },
  alert_title: { classes: () => alertTitleVariants() },
  alert_description: { classes: () => alertDescriptionVariants() },
  badge: { classes: () => badgeVariants({ variant: "outline" }) },
  field: { classes: () => fieldVariants() },
  field_label: { classes: () => fieldLabelVariants() },
  field_description: { classes: () => fieldDescriptionVariants() },
  field_error: { classes: () => fieldErrorVariants() },
  separator: { classes: () => separatorVariants() },
  dialog: {
    classes: () => cn(dialogContentVariants(), on("backdrop", dialogBackdropVariants())),
    identity: "inset-0 m-auto translate-x-0 translate-y-0",
  },
  dialog_header: { classes: () => dialogHeaderVariants() },
  dialog_title: { classes: () => dialogTitleVariants() },
  dialog_description: { classes: () => dialogDescriptionVariants() },
  dialog_body: { classes: () => dialogBodyVariants() },
  dialog_footer: { classes: () => dialogFooterVariants() },
}

function combinations(params: Record<string, string[]>): Props[] {
  return Object.entries(params).reduce<Props[]>(
    (all, [name, values]) =>
      all.flatMap((props) => values.map((value) => ({ ...props, [name]: value }))),
    [{}],
  )
}

function macro(name: string, { classes, params = {}, identity = "" }: Macro): string {
  const render = (props: Props) => cn(classes(props), identity)
  const names = Object.keys(params)
  const head = `{%- macro ${name}(${names.join(", ")}) -%}`
  if (names.length === 0) return `${head}\n${render({})}\n{%- endmacro -%}`
  const branches = combinations(params).map((props, i) => {
    const test = Object.entries(props)
      .map(([param, value]) => `${param} == "${value}"`)
      .join(" && ")
    return `{%- ${i === 0 ? "if" : "else if"} ${test} -%}\n${render(props)}`
  })
  return [head, ...branches, "{%- endif -%}", "{%- endmacro -%}"].join("\n")
}

// The design system's Mark: the logo's ink follows the text colour; the two bars keep their colours.
const markFills: Record<string, string> = {
  "#19181B": "",
  "#6300FF": "fill-logo-violet",
  "#EE430E": "fill-mark-orangered",
}

function mark(): string {
  const svg = readFileSync(
    fileURLToPath(import.meta.resolve("@zeabur/design-system/vendor/zeabur/logo.svg")),
    "utf8",
  )
  const paths = [...svg.matchAll(/<path d="([^"]+)" fill="([^"]+)"\/>/g)].map(([, d, fill]) => {
    const cls = markFills[fill ?? ""]
    if (cls === undefined) throw new Error(`logo.svg: unknown fill ${fill}`)
    return cls ? `<path d="${d}" class="${cls}"/>` : `<path d="${d}"/>`
  })
  if (paths.length !== 3) throw new Error(`logo.svg: expected 3 paths, found ${paths.length}`)
  return [
    "{#- Inline because the `brand-mark` utility's data: URL mask is blocked by the CSP (img-src 'self').",
    "    The mark is a Zeabur Inc. trademark. -#}",
    '{%- macro mark(cls = "") -%}',
    `<svg viewBox="0 0 32 32" fill="currentColor" aria-hidden="true" focusable="false" data-slot="mark" class="aspect-square shrink-0 text-main {{ cls }}">${paths.join("")}</svg>`,
    "{%- endmacro -%}",
  ].join("\n")
}

const out = new URL("../../crates/zeabur-identity-ui/templates/ds.html", import.meta.url)
const body = [
  "{#- Generated by ui/scripts/gen-classes.ts from @zeabur/design-system. Do not edit. -#}",
  ...Object.entries(macros).map(([name, spec]) => macro(name, spec)),
  mark(),
].join("\n\n")
await Bun.write(out, `${body}\n`)
