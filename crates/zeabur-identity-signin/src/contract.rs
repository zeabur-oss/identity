//! The TypeScript types of the JSON replies, generated from their JSON Schema and checked
//! against `ui/src/contract.ts`. The WebAuthn options are webauthn-rs types without a schema;
//! the web reads them as the browser's own options types.

use std::fmt::Write as _;

use schemars::generate::SchemaSettings;
use serde::{Deserialize, Serialize};

use crate::SignInResponse;
use crate::account::{Done, SignedIn as AccountSignedIn};
use crate::password::{
    Codes, Enrolment, SetUp as PasswordSetUp, SetupOptions, SignedIn as PasswordSignedIn,
};
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
    generator.subschema_for::<Enrolment>();
    generator.subschema_for::<Codes>();
    generator.subschema_for::<StartResponse>();
    let mut definitions: Vec<(String, Node)> = generator
        .take_definitions(true)
        .into_iter()
        .map(|(name, schema)| {
            let node = serde_json::from_str(&serde_json::to_string(&schema).unwrap()).unwrap();
            (name, node)
        })
        .collect();
    definitions.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = String::from(
        "// Generated from the server's reply types; do not edit.\n// Regenerate: ZEABUR_IDENTITY_WRITE_CONTRACT=1 cargo test -p zeabur-identity-signin contract\n",
    );
    for (name, schema) in &definitions {
        out.push('\n');
        doc(&mut out, schema, "");
        if schema.properties.is_some() {
            writeln!(out, "export type {name} = {}", object(schema, "")).unwrap();
        } else {
            writeln!(out, "export type {name} = {}", ty(schema, "")).unwrap();
        }
    }
    out
}

/// The JSON Schema keywords this generator renders; schemars hands out the schema of each type
/// as an untyped document, so it is read into this once.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Node {
    description: Option<String>,
    #[serde(rename = "$ref")]
    reference: Option<String>,
    #[serde(rename = "const")]
    constant: Option<Literal>,
    #[serde(rename = "enum")]
    variants: Option<Vec<Literal>>,
    #[serde(rename = "oneOf")]
    one_of: Option<Vec<Self>>,
    #[serde(rename = "anyOf")]
    any_of: Option<Vec<Self>>,
    #[serde(rename = "type")]
    ty: Option<Type>,
    properties: Option<Properties>,
    required: Vec<String>,
    items: Option<Box<Self>>,
}

/// The `properties` of an object, in the order the type declares them.
#[derive(Debug)]
struct Properties(Vec<(String, Node)>);

impl<'de> Deserialize<'de> for Properties {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct InOrder;

        impl<'de> serde::de::Visitor<'de> for InOrder {
            type Value = Properties;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object of schemas")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Properties, A::Error> {
                let mut fields = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    fields.push(entry);
                }
                Ok(Properties(fields))
            }
        }

        deserializer.deserialize_map(InOrder)
    }
}

/// A `const` or `enum` value: the schemas of the reply types hold scalars only.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum Literal {
    Text(String),
    Number(i64),
    Flag(bool),
    Null(()),
}

impl Literal {
    fn typescript(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

/// The `type` keyword: one name, or several.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Type {
    One(String),
    Many(Vec<String>),
}

fn doc(out: &mut String, schema: &Node, indent: &str) {
    if let Some(text) = &schema.description {
        writeln!(out, "{indent}/** {} */", text.replace('\n', " ")).unwrap();
    }
}

fn object(schema: &Node, indent: &str) -> String {
    let inner = format!("{indent}  ");
    let mut out = String::from("{\n");
    for (field, property) in &schema.properties.as_ref().unwrap().0 {
        doc(&mut out, property, &inner);
        let ty = ty(property, &inner);
        if schema.required.contains(field) {
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

fn ty(schema: &Node, indent: &str) -> String {
    if let Some(reference) = &schema.reference {
        return reference.rsplit('/').next().unwrap().to_owned();
    }
    if let Some(value) = &schema.constant {
        return value.typescript();
    }
    if let Some(values) = &schema.variants {
        return union(values.iter().map(Literal::typescript));
    }
    if let Some(alternatives) = schema.one_of.as_ref().or(schema.any_of.as_ref()) {
        return union(alternatives.iter().map(|a| ty(a, indent)));
    }
    match &schema.ty {
        Some(Type::One(name)) => named(name, schema, indent),
        Some(Type::Many(names)) => union(names.iter().map(|name| named(name, schema, indent))),
        None => panic!("unsupported schema without a type: {schema:?}"),
    }
}

fn named(name: &str, schema: &Node, indent: &str) -> String {
    match name {
        "string" => "string".to_owned(),
        "integer" | "number" => "number".to_owned(),
        "boolean" => "boolean".to_owned(),
        "null" => "null".to_owned(),
        "array" => format!("{}[]", ty(schema.items.as_ref().unwrap(), indent)),
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
