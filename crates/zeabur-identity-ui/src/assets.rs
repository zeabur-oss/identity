//! Static assets, built by `scripts/build-ui.sh`, committed, and embedded in the binary. Nothing is
//! loaded from other origins at run time.
//!
//! Styles and scripts are embedded brotli-encoded only, which a browser far away gets in fewer
//! round trips; a client without brotli gets them decoded once and kept.

use std::io::Read as _;
use std::sync::{LazyLock, OnceLock};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::Path;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use zeabur_identity_core::crypto::{hex, sha256};

/// Buffer of the brotli decoder.
const DECODE_BUFFER: usize = 16 * 1024;

struct Asset {
    name: &'static str,
    content_type: &'static str,
    /// The file, or its brotli encoding when `brotli`.
    stored: &'static [u8],
    brotli: bool,
    /// The file decoded from `stored`, once a client without brotli asked for it.
    decoded: OnceLock<Option<Bytes>>,
}

impl Asset {
    fn decoded(&self) -> Option<Bytes> {
        self.decoded
            .get_or_init(|| {
                let mut file = Vec::new();
                brotli_decompressor::Decompressor::new(self.stored, DECODE_BUFFER)
                    .read_to_end(&mut file)
                    .ok()?;
                Some(file.into())
            })
            .clone()
    }
}

static ASSETS: [Asset; 5] = [
    Asset {
        name: "app.css",
        content_type: "text/css; charset=utf-8",
        stored: include_bytes!("../assets/app.css.br"),
        brotli: true,
        decoded: OnceLock::new(),
    },
    Asset {
        name: "login.js",
        content_type: "text/javascript; charset=utf-8",
        stored: include_bytes!("../assets/login.js.br"),
        brotli: true,
        decoded: OnceLock::new(),
    },
    Asset {
        name: "setup.js",
        content_type: "text/javascript; charset=utf-8",
        stored: include_bytes!("../assets/setup.js.br"),
        brotli: true,
        decoded: OnceLock::new(),
    },
    Asset {
        name: "account.js",
        content_type: "text/javascript; charset=utf-8",
        stored: include_bytes!("../assets/account.js.br"),
        brotli: true,
        decoded: OnceLock::new(),
    },
    Asset {
        name: "Geist-Variable.woff2",
        content_type: "font/woff2",
        stored: include_bytes!("../assets/Geist-Variable.woff2"),
        brotli: false,
        decoded: OnceLock::new(),
    },
];

/// Content hashes appended to asset URLs, so they can be cached forever.
#[derive(Debug, Clone)]
pub struct Versions {
    /// `app.css`.
    pub css: String,
    /// `login.js`.
    pub login_js: String,
    /// `setup.js`.
    pub setup_js: String,
    /// `account.js`.
    pub account_js: String,
}

/// The embedded assets' versions, hashed once.
pub static VERSIONS: LazyLock<Versions> = LazyLock::new(Versions::compute);

impl Versions {
    fn compute() -> Self {
        let version = |name: &str| {
            ASSETS
                .iter()
                .find(|a| a.name == name)
                .map_or_else(String::new, |a| {
                    hex(&sha256(a.stored)).chars().take(16).collect()
                })
        };
        Self {
            css: version("app.css"),
            login_js: version("login.js"),
            setup_js: version("setup.js"),
            account_js: version("account.js"),
        }
    }
}

/// `GET /assets/{name}`, for every embedded asset.
pub fn router() -> Router {
    Router::new().route("/assets/{name}", get(serve))
}

/// `GET /assets/{name}`.
pub async fn serve(Path(name): Path<String>, request: HeaderMap) -> Response {
    let Some(asset) = ASSETS.iter().find(|a| a.name == name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let encoded = asset.brotli && accepts_brotli(&request);
    let mut response = if !asset.brotli || encoded {
        Body::from(asset.stored).into_response()
    } else {
        match asset.decoded() {
            Some(file) => Body::from(file).into_response(),
            None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    };
    let headers = response.headers_mut();
    if asset.brotli {
        headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    }
    if encoded {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
    }
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(asset.content_type),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response
}

/// Whether `Accept-Encoding` lists `br` without `q=0`.
fn accepts_brotli(request: &HeaderMap) -> bool {
    request
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|item| {
            let mut parts = item.split(';').map(str::trim);
            parts
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("br"))
                && parts.all(|p| {
                    p.strip_prefix("q=")
                        .is_none_or(|q| q.parse::<f32>().is_ok_and(|q| q > 0.0))
                })
        })
}
