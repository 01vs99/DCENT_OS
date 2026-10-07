//! Keep the plaintext backend behind the device HTTPS proxy. Never trust a
//! caller-supplied forwarded-proto header as proof of encrypted transport.
use axum::{body::Body, extract::ConnectInfo, http::Request, middleware::Next, response::Response};
use std::net::SocketAddr;

pub(crate) fn backend_bind(configured: &str, release: bool, password: bool) -> String {
    if release || password {
        "127.0.0.1".to_owned()
    } else {
        configured.to_owned()
    }
}

fn remote_plaintext_allowed(release: bool, password: bool, path: &str) -> bool {
    !release && !password && !path.starts_with("/api/auth/")
}

async fn with_posture(
    request: Request<Body>,
    next: Next,
    release: bool,
    password: bool,
) -> Response {
    let loopback = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|peer| peer.0.ip().is_loopback());
    if !loopback && !remote_plaintext_allowed(release, password, request.uri().path()) {
        return Response::builder()
            .status(426)
            .header("Content-Type", "application/json")
            .header("Cache-Control", "no-store")
            .header("Connection", "close")
            .body(Body::from(
                r#"{"error":"Use the dashboard HTTPS endpoint on port 443"}"#,
            ))
            .expect("fixed HTTP response");
    }
    next.run(request).await
}

pub(crate) async fn middleware(request: Request<Body>, next: Next) -> Response {
    // Recheck on each request: setting a password closes a lab listener without
    // waiting for a daemon restart. Loopback still passes normal bearer auth.
    with_posture(
        request,
        next,
        crate::auth::is_release_image(),
        crate::auth::is_password_set(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{middleware::from_fn, routing::any, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn dashboard_tls_actual_guard_preserves_loopback_and_refuses_forwarded_spoof() {
        for (release, password) in [(false, false), (true, false), (false, true), (true, true)] {
            for peer in ["127.0.0.1:31001", "[::1]:31001", "192.0.2.20:31001"] {
                for path in ["/api/status", "/api/auth/setup", "/api/auth/session"] {
                    let address: SocketAddr = peer.parse().unwrap();
                    let app = Router::new()
                        .route(path, any(|| async { "owner reached" }))
                        .layer(from_fn(move |request, next| {
                            with_posture(request, next, release, password)
                        }));
                    let mut request = Request::builder()
                        .uri(path)
                        .method("POST")
                        .header("X-Forwarded-Proto", "https")
                        .header("X-Forwarded-For", "127.0.0.1")
                        .body(Body::empty())
                        .unwrap();
                    request.extensions_mut().insert(ConnectInfo(address));
                    let response = app.oneshot(request).await.unwrap();
                    let allowed = address.ip().is_loopback()
                        || (!release && !password && path == "/api/status");
                    assert_eq!(response.status().as_u16(), if allowed { 200 } else { 426 });
                }
            }
        }
    }

    #[test]
    fn dashboard_tls_release_and_password_bind_only_loopback() {
        assert_eq!(backend_bind("0.0.0.0", false, false), "0.0.0.0");
        assert_eq!(backend_bind("192.0.2.5", true, false), "127.0.0.1");
        assert_eq!(backend_bind("::", false, true), "127.0.0.1");
    }
}
