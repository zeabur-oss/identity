// `as unknown as T` and `as never` tell the compiler to stop checking. Narrow the type or use
// `satisfies` instead. (`as any` is `typescript/no-explicit-any`.)
const rule = {
  meta: {
    type: "problem",
    docs: { description: "Disallow `as unknown as T` and `as never`." },
  },
  create(context) {
    return {
      TSAsExpression(node) {
        const type = node.typeAnnotation.type
        const inner = node.expression
        if (type === "TSNeverKeyword") {
          context.report({ node, message: "`as never` silences the type checker." })
        } else if (
          inner.type === "TSAsExpression" &&
          inner.typeAnnotation.type === "TSUnknownKeyword"
        ) {
          context.report({ node, message: "`as unknown as` silences the type checker." })
        }
      },
    }
  },
}

export default { meta: { name: "casts" }, rules: { "no-unsound-cast": rule } }
