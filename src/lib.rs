#[allow(dead_code)]
pub mod response {
    use axum::response::IntoResponse;
    use hyper::StatusCode;

    pub const SUCCESS: &str = "Success";
    pub const ERROR: &str = "Error";

    #[axum::debug_handler]
    pub async fn not_found(message: String) -> impl IntoResponse {
        (
            StatusCode::NOT_FOUND,
            message, 
            //default message: "The requested resource was not found, nothing to see here.",
        )
    }


    pub async fn internal_server_error(message: String) -> impl IntoResponse {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            message,
            //default message: "An internal server error occurred. The server encountered an unexpected condition that prevented it from fulfilling the request."
        )
    }

    pub async fn bad_request(message: String) -> impl IntoResponse {
        (
            StatusCode::BAD_REQUEST,
            message,
            //default message: "The request was invalid or cannot be served."
        )
    }

    pub async fn unauthorized(message: String) -> impl IntoResponse {
        (
            StatusCode::UNAUTHORIZED,
            message,
            //default message: "Authentication is required and has failed or has not yet been provided."

        )
    }
}
