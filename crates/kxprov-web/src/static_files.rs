use axum::body::Body;
use axum::http::{header, Response, StatusCode};
use axum::response::IntoResponse;

struct Asset {
    bytes: &'static [u8],
    content_type: &'static str,
}

fn asset(path: &str) -> Option<Asset> {
    Some(match path {
        "favicon.svg" => Asset {
            bytes: include_bytes!("../assets/favicon.svg"),
            content_type: "image/svg+xml",
        },
        "favicon-32.png" => Asset {
            bytes: include_bytes!("../assets/favicon-32.png"),
            content_type: "image/png",
        },
        "favicon-16.png" => Asset {
            bytes: include_bytes!("../assets/favicon-16.png"),
            content_type: "image/png",
        },
        "icon-192.png" => Asset {
            bytes: include_bytes!("../assets/icon-192.png"),
            content_type: "image/png",
        },
        "icon-512.png" => Asset {
            bytes: include_bytes!("../assets/icon-512.png"),
            content_type: "image/png",
        },
        "logo.svg" => Asset {
            bytes: include_bytes!("../assets/logo.svg"),
            content_type: "image/svg+xml",
        },
        "logo-dark.svg" => Asset {
            bytes: include_bytes!("../assets/logo-dark.svg"),
            content_type: "image/svg+xml",
        },
        "logo-badge.svg" => Asset {
            bytes: include_bytes!("../assets/logo-badge.svg"),
            content_type: "image/svg+xml",
        },
        "site.css" => Asset {
            bytes: include_bytes!("../assets/site.css"),
            content_type: "text/css; charset=utf-8",
        },
        "plan-expiry.js" => Asset {
            bytes: include_bytes!("../assets/plan-expiry.js"),
            content_type: "application/javascript; charset=utf-8",
        },
        _ => return None,
    })
}

pub async fn serve_static(path: String) -> impl IntoResponse {
    let Some(file) = asset(path.trim_start_matches('/')) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, file.content_type)
        .header(header::CACHE_CONTROL, "public, max-age=3600")
        .body(Body::from(file.bytes))
        .unwrap()
        .into_response()
}
