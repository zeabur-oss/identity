//! The TypeScript types of the JSON requests and replies, and the table of the routes the pages
//! call, generated from their JSON Schema and checked against `ui/src/contract.ts`. The WebAuthn
//! options and credentials are webauthn-rs types without a schema; they appear as `WebAuthnJson`,
//! which the web converts to and from the browser's own types.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use schemars::generate::SchemaSettings;
use schemars::{JsonSchema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use zeabur_identity_core::protocol::UPSTREAM_START_ROUTE;

use crate::account::{
    AddRequest as AddPasskey, AssertionRequest, Done, RenameRequest, SignedIn as AccountSignedIn,
};
use crate::password::{
    AddRequest as AddPassword, ChangeRequest, Codes, ConfirmRequest, Enrolment, OptionsRequest,
    RemoveRequest, ReplaceRequest, SetUp as PasswordSetUp, SetupOptions,
    SetupRequest as PasswordSetup, SignInRequest as PasswordSignIn, SignedIn as PasswordSignedIn,
};
use crate::problem::ProblemBody;
use crate::upstream::{AccountStartRequest, StartRequest, StartResponse};
use crate::{
    SetupOptionsRequest, SetupRequest as PasskeySetup, SetupResponse, SignInRequest,
    SignInResponse, WebAuthnJson,
};

const PATH: &str = "ui/src/contract.ts";

/// The schemas of the requests, read as the server reads them, and of the replies, as it writes
/// them: a field the server fills in when it is missing is optional only in a request.
struct Generators {
    requests: SchemaGenerator,
    replies: SchemaGenerator,
}

/// One JSON route a page calls, with the TypeScript names of its request and reply bodies.
struct Route {
    key: &'static str,
    method: &'static str,
    path: &'static str,
    request: String,
    reply: String,
}

impl Generators {
    /// The route `method path` as `key`, which takes a `Q` and answers with an `R`. `()` is no
    /// body.
    fn route<Q: JsonSchema, R: JsonSchema>(
        &mut self,
        key: &'static str,
        method: &'static str,
        path: &'static str,
    ) -> Route {
        let request = reference(&self.requests.subschema_for::<Q>());
        let reply = reference(&self.replies.subschema_for::<R>());
        Route {
            key,
            method,
            path,
            request,
            reply,
        }
    }
}

/// The TypeScript name of a type the generator saw: its definition, or `null` for `()`.
fn reference(schema: &schemars::Schema) -> String {
    ty(&node(schema), "", Side::Reply)
}

fn node(schema: &schemars::Schema) -> Node {
    serde_json::from_value(schema.as_value().clone()).unwrap()
}

/// Every JSON route the pages call. The `…/options` routes, `/account/reauth` and the sign-in and
/// setup steps are `POST`, as they start or finish a ceremony; a credential or session on the
/// account page is a resource, changed with `PATCH` or `PUT` and removed with `DELETE`.
fn routes(g: &mut Generators) -> Vec<Route> {
    vec![
        g.route::<(), WebAuthnJson>("loginOptions", "POST", "/login/options"),
        g.route::<SignInRequest, SignInResponse>("login", "POST", "/login"),
        g.route::<PasswordSignIn, PasswordSignedIn>("passwordLogin", "POST", "/login/password"),
        g.route::<StartRequest, StartResponse>("upstreamStart", "POST", UPSTREAM_START_ROUTE),
        g.route::<SetupOptionsRequest, WebAuthnJson>("setupOptions", "POST", "/setup/options"),
        g.route::<PasskeySetup, SetupResponse<'static>>("setup", "POST", "/setup"),
        g.route::<OptionsRequest, SetupOptions>(
            "passwordSetupOptions",
            "POST",
            "/setup/password/options",
        ),
        g.route::<PasswordSetup, PasswordSetUp<'static>>(
            "passwordSetup",
            "POST",
            "/setup/password",
        ),
        g.route::<(), WebAuthnJson>("sessionOptions", "POST", "/account/session/options"),
        g.route::<AssertionRequest, AccountSignedIn>("signIn", "POST", "/account/session"),
        g.route::<PasswordSignIn, AccountSignedIn>(
            "passwordSignIn",
            "POST",
            "/account/session/password",
        ),
        g.route::<(), Done>("signOut", "DELETE", "/account/session"),
        g.route::<(), WebAuthnJson>("reauthOptions", "POST", "/account/reauth/options"),
        g.route::<AssertionRequest, Done>("reauth", "POST", "/account/reauth"),
        g.route::<(), WebAuthnJson>("addPasskeyOptions", "POST", "/account/passkeys/options"),
        g.route::<AddPasskey, Done>("addPasskey", "POST", "/account/passkeys"),
        g.route::<RenameRequest, Done>("renamePasskey", "PATCH", "/account/passkeys/{name}"),
        g.route::<(), Done>("removePasskey", "DELETE", "/account/passkeys/{name}"),
        g.route::<(), Done>("revokeOtherSessions", "DELETE", "/account/sessions"),
        g.route::<(), Done>("revokeSession", "DELETE", "/account/sessions/{name}"),
        g.route::<AccountStartRequest, StartResponse>("link", "POST", "/account/links/start"),
        g.route::<(), Done>("unlink", "DELETE", "/account/links/{name}"),
        g.route::<(), SetupOptions>("addPasswordOptions", "POST", "/account/password/options"),
        g.route::<AddPassword, Codes>("addPassword", "POST", "/account/password"),
        g.route::<ChangeRequest, Done>("changePassword", "PUT", "/account/password"),
        g.route::<RemoveRequest, Done>("removePassword", "DELETE", "/account/password"),
        g.route::<(), Enrolment>(
            "authenticatorOptions",
            "POST",
            "/account/authenticator/options",
        ),
        g.route::<ReplaceRequest, Codes>("replaceAuthenticator", "PUT", "/account/authenticator"),
        g.route::<ConfirmRequest, Codes>(
            "regenerateRecoveryCodes",
            "POST",
            "/account/recovery-codes",
        ),
    ]
}

fn typescript() -> String {
    let mut g = Generators {
        requests: SchemaSettings::draft2020_12()
            .for_deserialize()
            .into_generator(),
        replies: SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator(),
    };
    // Replies the pages read that no route table entry names.
    g.replies.subschema_for::<ProblemBody>();
    g.replies.subschema_for::<PasswordSignedIn>();
    let routes = routes(&mut g);

    let mut definitions = BTreeMap::new();
    for (side, generator) in [
        (Side::Request, &mut g.requests),
        (Side::Reply, &mut g.replies),
    ] {
        for (name, schema) in generator.take_definitions(true) {
            let schema: Node = serde_json::from_value(schema).unwrap();
            let mut text = String::new();
            doc(&mut text, &schema, "");
            if schema.properties.is_some() {
                writeln!(text, "export type {name} = {}", object(&schema, "", side)).unwrap();
            } else {
                writeln!(text, "export type {name} = {}", ty(&schema, "", side)).unwrap();
            }
            if let Some(other) = definitions.insert(name.clone(), text.clone()) {
                assert_eq!(
                    other, text,
                    "{name} reads differently as a request and a reply"
                );
            }
        }
    }

    let mut out = String::from(
        "// Generated from the server's request and reply types and its routes; do not edit.\n// Regenerate: ZEABUR_IDENTITY_WRITE_CONTRACT=1 cargo test -p zeabur-identity-signin contract\n",
    );
    for text in definitions.values() {
        out.push('\n');
        out.push_str(text);
    }
    out.push_str(
        "\n/** The JSON routes the pages call. The caller fills in the parameters in braces. */\nexport const routes = {\n",
    );
    for route in &routes {
        writeln!(
            out,
            "  {}: {{ method: \"{}\", path: \"{}\" }},",
            route.key, route.method, route.path
        )
        .unwrap();
    }
    out.push_str("} as const\n\n/** The body each route takes; `null` when it takes none. */\nexport type Requests = {\n");
    for route in &routes {
        writeln!(out, "  {}: {}", route.key, route.request).unwrap();
    }
    out.push_str(
        "}\n\n/** The body each route answers with when it succeeds. */\nexport type Replies = {\n",
    );
    for route in &routes {
        writeln!(out, "  {}: {}", route.key, route.reply).unwrap();
    }
    out.push_str("}\n");
    out
}

/// Which way a type travels. A request field the server fills in when it is missing may be left
/// out or sent as `null`; a reply skips an empty field and never sends it as `null`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Request,
    Reply,
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

fn object(schema: &Node, indent: &str, side: Side) -> String {
    let inner = format!("{indent}  ");
    let Some(properties) = &schema.properties else {
        return "Record<string, unknown>".to_owned();
    };
    let mut out = String::from("{\n");
    for (field, property) in &properties.0 {
        doc(&mut out, property, &inner);
        let ty = ty(property, &inner, side);
        if schema.required.contains(field) {
            writeln!(out, "{inner}{field}: {ty}").unwrap();
        } else if side == Side::Request {
            writeln!(out, "{inner}{field}?: {ty}").unwrap();
        } else {
            let ty = ty.strip_suffix(" | null").unwrap_or(&ty);
            writeln!(out, "{inner}{field}?: {ty}").unwrap();
        }
    }
    out.push_str(indent);
    out.push('}');
    out
}

fn ty(schema: &Node, indent: &str, side: Side) -> String {
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
        return union(alternatives.iter().map(|a| ty(a, indent, side)));
    }
    match &schema.ty {
        Some(Type::One(name)) => named(name, schema, indent, side),
        Some(Type::Many(names)) => {
            union(names.iter().map(|name| named(name, schema, indent, side)))
        }
        None => panic!("unsupported schema without a type: {schema:?}"),
    }
}

fn named(name: &str, schema: &Node, indent: &str, side: Side) -> String {
    match name {
        "string" => "string".to_owned(),
        "integer" | "number" => "number".to_owned(),
        "boolean" => "boolean".to_owned(),
        "null" => "null".to_owned(),
        "array" => format!("{}[]", ty(schema.items.as_ref().unwrap(), indent, side)),
        "object" => object(schema, indent, side),
        other => panic!("unsupported schema type {other}"),
    }
}

fn union(parts: impl Iterator<Item = String>) -> String {
    parts.collect::<Vec<_>>().join(" | ")
}

#[test]
fn contract_matches_the_server_types_and_routes() {
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
