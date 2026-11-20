//! The TypeScript types of the JSON replies, generated from their JSON Schema and checked
//! against `ui/src/contract.ts`. The WebAuthn options are webauthn-rs types without a schema;
//! the web reads them as the browser's own options types.

use std::fmt::Write as _;

use schemars::generate::SchemaSettings;
use serde_json::Value;

use crate::SignInResponse;
use crate::account::{Done, SignedIn as AccountSignedIn};
use crate::password::{SetUp as PasswordSetUp, SetupOptions, SignedIn as PasswordSignedIn};
use crate::problem::ProblemBody;
use crate::upstream::StartResponse;

const PATH: &str = "ui/src/contract.ts";

fn typescript() -> String {
    let mut generator = SchemaSettings::draft2020_12()
        .for_serialize()
        .into_generator();
    generator.subschema_for::<ProblemBody>();
    generator.subschema_for::<SignInResponse>();
    generator.subschema_for::<Done>();
    generator.subschema_for::<AccountSignedIn>();
    generator.subschema_for::<PasswordSignedIn>();
    generator.subschema_for::<PasswordSetUp<'_>>();
    generator.subschema_for::<SetupOptions>();
    generator.subschema_for::<StartResponse>();
    let mut definitions: Vec<_> = generator.take_definitions(true).into_iter().collect();
    definitions.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = String::from(
        "// Generated from the server's reply types; do not edit.\n// Regenerate: ZEABUR_IDENTITY_WRITE_CONTRACT=1 cargo test -p zeabur-identity-signin contract\n",
    );
    for (name, schema) in &definitions {
        out.push('\n');
        doc(&mut out, schema, "");
        if member(schema, "properties").is_some() {
            writeln!(out, "export type {name} = {}", object(schema, "")).unwrap();
        } else {
            writeln!(out, "export type {name} = {}", ty(schema, "")).unwrap();
        }
    }
    out
}

/// A keyword of a JSON Schema document. Only the keywords this generator renders are read.
#[expect(
    clippy::disallowed_methods,
    reason = "JSON Schema is open-ended, so the generator reads the keywords it renders by name"
)]
fn member<'a>(schema: &'a Value, keyword: &str) -> Option<&'a Value> {
    schema.get(keyword)
}

fn doc(out: &mut String, schema: &Value, indent: &str) {
    if let Some(text) = member(schema, "description").and_then(Value::as_str) {
        writeln!(out, "{indent}/** {} */", text.replace('\n', " ")).unwrap();
    }
}

fn object(schema: &Value, indent: &str) -> String {
    let required: Vec<&str> = schema["required"].as_array().map_or_else(Vec::new, |list| {
        list.iter().filter_map(Value::as_str).collect()
    });
    let inner = format!("{indent}  ");
    let mut out = String::from("{\n");
    for (field, property) in schema["properties"].as_object().unwrap() {
        doc(&mut out, property, &inner);
        let ty = ty(property, &inner);
        if required.contains(&field.as_str()) {
            writeln!(out, "{inner}{field}: {ty}").unwrap();
        } else {
            // Skipped when empty, never sent as null.
            let ty = ty.strip_suffix(" | null").unwrap_or(&ty);
            writeln!(out, "{inner}{field}?: {ty}").unwrap();
        }
    }
    out.push_str(indent);
    out.push('}');
    out
}

fn ty(schema: &Value, indent: &str) -> String {
    if let Some(reference) = member(schema, "$ref").and_then(Value::as_str) {
        return reference.rsplit('/').next().unwrap().to_owned();
    }
    if let Some(value) = member(schema, "const") {
        return value.to_string();
    }
    if let Some(values) = member(schema, "enum").and_then(Value::as_array) {
        return union(values.iter().map(Value::to_string));
    }
    if let Some(alternatives) = member(schema, "oneOf")
        .or_else(|| member(schema, "anyOf"))
        .and_then(Value::as_array)
    {
        return union(alternatives.iter().map(|a| ty(a, indent)));
    }
    match &schema["type"] {
        Value::String(name) => named(name, schema, indent),
        Value::Array(names) => union(
            names
                .iter()
                .map(|name| named(name.as_str().unwrap(), schema, indent)),
        ),
        other @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_)) => {
            panic!("unsupported schema type {other} in {schema}")
        }
    }
}

fn named(name: &str, schema: &Value, indent: &str) -> String {
    match name {
        "string" => "string".to_owned(),
        "integer" | "number" => "number".to_owned(),
        "boolean" => "boolean".to_owned(),
        "null" => "null".to_owned(),
        "array" => format!("{}[]", ty(&schema["items"], indent)),
        "object" => object(schema, indent),
        other => panic!("unsupported schema type {other}"),
    }
}

fn union(parts: impl Iterator<Item = String>) -> String {
    parts.collect::<Vec<_>>().join(" | ")
}

#[test]
fn contract_matches_the_reply_types() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(PATH);
    let generated = typescript();
    if std::env::var_os("ZEABUR_IDENTITY_WRITE_CONTRACT").is_some() {
        std::fs::write(&path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == generated,
        "{PATH} is stale: run `ZEABUR_IDENTITY_WRITE_CONTRACT=1 cargo test -p zeabur-identity-signin contract`"
    );
}
