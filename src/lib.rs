#[allow(dead_code)]
mod response {
    use hyper::StatusCode;
    use axum::response::IntoResponse;

    pub const SUCCESS: &str = "Success";
    pub const ERROR: &str = "Error";
    async fn not_found() -> impl IntoResponse {
        (
            StatusCode::NOT_FOUND,
            "The requested resource was not found.",
        )
    }

    async fn internal_server_error() -> impl IntoResponse {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "An internal server error occurred.",
        )
    }

    async fn bad_request() -> impl IntoResponse {
        (
            StatusCode::BAD_REQUEST,
            "The request was invalid or cannot be served.",
        )
    }

    async fn unauthorized() -> impl IntoResponse {
        (
            StatusCode::UNAUTHORIZED,
            "Authentication is required and has failed or has not yet been provided.",
        )
    }
}
