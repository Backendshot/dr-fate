#[allow(dead_code)]
pub mod response {
    use axum::response::IntoResponse;
    use hyper::StatusCode;

    pub const SUCCESS: &str = "Success";
    pub const ERROR: &str = "Error";
    pub async fn not_found() -> impl IntoResponse {
        (
            StatusCode::NOT_FOUND,
            "The requested resource was not found, nothing to see here.",
        )
    }

    pub async fn internal_server_error() -> impl IntoResponse {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "An internal server error occurred.",
        )
    }

    pub async fn bad_request() -> impl IntoResponse {
        (
            StatusCode::BAD_REQUEST,
            "The request was invalid or cannot be served.",
        )
    }

    pub async fn unauthorized() -> impl IntoResponse {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication is required and has failed or has not yet been provided.",
        )
    }
}
