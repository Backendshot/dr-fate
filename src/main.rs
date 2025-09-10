use argon2::{Argon2, PasswordVerifier};
use async_mailer::Mailer;
use axum::{
    extract::{Multipart, Path, State, Query},
    http::{header::HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, patch, post},
    Json, Router,
};
use dotenvy::dotenv;
use fancy_regex::Regex;
use async_mailer::{IntoMessage, MessageBuilder, SmtpMailer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, Postgres, Row, Transaction, Executor};
use tower::ServiceBuilder;
use tower_governor::{governor::GovernorConfig, GovernorLayer};
use tower_http::{
    compression::{CompressionLayer, CompressionLevel},
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer},
    validate_request::ValidateRequestHeaderLayer,
};
use tracing::Level;
use std::fmt::Display;
use std::time::Duration;
use std::{collections::HashMap, env, net::SocketAddr, sync::Arc};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;
use reqwest::header;

#[derive(Clone)]
struct AppState {
    // db: Arc<RwLock<HashMap<u64, Item>>>,
    // id_counter: Arc<AtomicU64>,
    db: Arc<PgPool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Todo {
    id: i32,
    #[serde(rename = "userId")]
    user_id: i32,
    title: Option<String>,
    completed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistrationRequest {
    id: Option<i32>,
    username: String,
    first_name: String,
    middle_name: Option<String>,
    last_name: String,
    email: String,
    email_verified: bool,
    email_verified_at: Option<chrono::NaiveDateTime>,
    birthday: Option<chrono::NaiveDate>,
    created_at: chrono::NaiveDateTime,
    updated_at: chrono::NaiveDateTime,
    image: Option<String>,
    role_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EmailVerification {
    user_id: i32,
    from_system: EmailVerificationSource,
    sender_email: String,
    receiver_email: String,
    status: String,
    subject: String,
    body: String,
    requested_at: chrono::NaiveDateTime,
    verified_at: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserCredentials {
    id: Option<i32>,
    user_id: i32,
    username: String,
    password: String,
    jwt_token: Option<String>,
    active_session: bool,
    active_session_deleted: bool,
    created_at: chrono::NaiveDateTime,
    updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum EmailVerificationSource {
    Registration,
    PasswordReset,
}

impl Display for EmailVerificationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EmailVerificationSource::Registration => write!(f, "registration"),
            EmailVerificationSource::PasswordReset => write!(f, "password_reset"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoginPayload {
    user_id: Option<i32>,
    username: String,
    password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoginResponse {
    user_id: i32,
    username: String,
    jwt_token: String,
    active_session: String,
    active_session_deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogoutPayload {
    user_id: i32,
    jwt_token: String,
}

// #[derive(Debug, Clone, Serialize, Deserialize)]
// struct User {
//     id: Option<i32>,
//     username: String,
//     first_name: String,
//     middle_name: Option<String>,
//     last_name: String,
//     email: String,
//     email_verified: bool,
//     email_verified_at: Option<chrono::NaiveDateTime>,
//     birthday: Option<chrono::NaiveDate>,
//     created_at: chrono::NaiveDateTime,
//     updated_at: chrono::NaiveDateTime,
//     image: Option<String>,
//     role_type: String,
// }

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GlobalResponse {
    status: String,
    message: String,
    data: Option<serde_json::Value>,
    errors: Option<serde_json::Value>,
}

#[tokio::main]
async fn main() {
    // setup logging
    tracing_subscriber::registry().with(fmt::layer()).init();

    // initial state
    // let state = AppState {
    //     db: Arc::new(RwLock::new(HashMap::new())),
    //     id_counter: Arc::new(AtomicU64::new(1)),
    // };

    // set DATABASE_URL in env, e.g.:
    // postgres://postgres:password@db.host.supabase.co:5432/postgres?sslmode=require
    dotenv().ok();
    let database_url =
        env::var("POSTGRES_URL_NON_POOLING").expect("DB_URL env var must be set (from Supabase)");
    println!("Database URL: {}", database_url);
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    let state = AppState { db: Arc::new(pool) };

    // Services
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_request(DefaultOnRequest::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO))
        .on_failure(DefaultOnFailure::new().level(Level::ERROR));

    let cors_layer = CorsLayer::permissive();

    let compression_layer = CompressionLayer::new()
                                .zstd(true)
                                .gzip(true)
                                .quality(CompressionLevel::Default); // uses zstd with gzip as backup

    // let set_request_id_layer = SetRequestIdLayer::new( HeaderName::from_static("x-request-id", );

    // let propagate_request_id_layer: PropagateRequestIdLayer = PropagateRequestIdLayer::new(HeaderName::from_static("x-request-id"));

    let timeout_layer = TimeoutLayer::new(Duration::from_secs(30)); // 30 seconds timeout

    // let rate_limit_layer = RateLimitLayer::new(100, Duration::from_secs(60)); // 100 requests per minute

    let governor_config = GovernorConfig::default();

    let rate_limit_layer = GovernorLayer::new(governor_config);

    // Routes
    let login_route = Router::new()
        .route("/login", post(login))
        .route(
            "/profile-image/{user_id}",
            get(retrieve_profile_image).layer(compression_layer.clone()),
        )
        .route(
            "/profile-image/update/{user_id}",
            patch(update_profile_image).layer(compression_layer.clone()),
        )
        .route("/logout", post(logout))
        .route("/audit/{user_id}", get(audit_user));

    let registration_route = Router::new()
        .route("/register", post(register))
        .route("/email/verify", post(verify_email));

    let todo_api_route = Router::new()
        .route("/", get(fetch_todos))
        .route("/{id}", get(fetch_todo_by_id))
        .route("/import-data-todos", get(import_todo_data));

    let todo_db_route = Router::new()
        .route("/readall", get(read_all_todos))
        .route("/read/{user_id}", get(view_all_todos_by_id))
        .route("/create", post(create_todo))
        .route("/update/{id}", patch(update_todo))
        .route("/delete/{id}", delete(delete_todo))
        .route("/delete-table/{id}", patch(update_delete_status));

    let app = Router::new()
        .nest("/user", login_route)
        .nest("/api/user", registration_route)
        .nest("/todos", todo_api_route)
        .nest("/api/v2", todo_db_route)
        .with_state(state)
        .layer(ServiceBuilder::new() //order matters
            .layer(trace_layer)
            .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
            .layer(cors_layer)
            .layer(compression_layer)  // 10 MB limit (uses zstd with gzip as backup)
            .layer(rate_limit_layer) // 100 requests per minute
            .layer(timeout_layer) // 30 seconds timeout
            .layer(ValidateRequestHeaderLayer::bearer("UMTC"))
            .layer(ValidateRequestHeaderLayer::accept("application/json"))
        );

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::info!("listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}


/* Handlers */

async fn fetch_todos() -> Result<impl IntoResponse, (StatusCode, String)> {
    // let items = sqlx::query("SELECT id, name, description FROM items WHERE deleted = FALSE")
    //     .fetch_all(&*state.db)
    //     .await
    //     .map_err(|e| {
    //         (
    //             StatusCode::INTERNAL_SERVER_ERROR,
    //             format!("Failed to fetch items: {}", e),
    //         )
    //     })?
    //     .into_iter()
    //     .map(|row| Item {
    //         id: row.get("id"),
    //         name: row.get("name"),
    //         description: row.get("description"),
    //     })
    //     .collect::<Vec<_>>();

    // (StatusCode::OK, Json(items))
    let todos = reqwest::get("https://jsonplaceholder.typicode.com/todos")
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch todos: {}", e),
            )
        })?
        .json::<Vec<HashMap<String, serde_json::Value>>>()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse todos: {}", e),
            )
        })?;

    Ok((StatusCode::OK, Json(todos)))
}

async fn fetch_todo_by_id(Path(id): Path<u64>) -> Result<impl IntoResponse, (StatusCode, String)> {
    // let todo = sqlx::query("SELECT id, name, description FROM items WHERE id = $1 AND deleted = FALSE")
    //     .bind(id)
    //     .fetch_one(&*state.db)
    //     .await
    //     .map_err(|e| {
    //         (
    //             StatusCode::INTERNAL_SERVER_ERROR,
    //             format!("Failed to fetch item: {}", e),
    //         )
    //     })?;

    let todos = reqwest::get("https://jsonplaceholder.typicode.com/todos")
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch todos: {}", e),
            )
        })?
        .json::<Vec<HashMap<String, serde_json::Value>>>()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse todos: {}", e),
            )
        })?;

    let todo = todos
        .into_iter()
        .find(|todo| todo.get("id").and_then(|v| v.as_u64()) == Some(id))
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("Todo with id {} not found", id),
            )
        })?;

    Ok((StatusCode::OK, Json(todo)))
}

async fn import_todo_data(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let todos = reqwest::get("https://jsonplaceholder.typicode.com/todos")
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch todos: {}", e),
            )
        })?
        .json::<Vec<HashMap<String, serde_json::Value>>>()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse todos: {}", e),
            )
        })?;

    let mut tx: Transaction<'_, Postgres> = state.db.begin().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to start transaction: {}", e),
        )
    })?;

    for todo in todos {
        let user_id = todo.get("userId").and_then(|v| v.as_i64()).unwrap_or(0);
        let title = todo
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let completed = todo
            .get("completed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        sqlx::query(
            "INSERT INTO todos (user_id, title, completed, is_deleted) VALUES ($1, $2, $3, $4)",
        )
        .bind(user_id)
        .bind(&title)
        .bind(completed)
        .bind(false)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to execute statement: {}", e),
            )
        })?;
    }

    tx.commit().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to commit transaction: {}", e),
        )
    })?;

    Ok((StatusCode::OK, "Imported todos successfully"))
}

async fn read_all_todos(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let items = sqlx::query("SELECT user_id, id, title, completed FROM get_all_todos()")
        .fetch_all(&*state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch items: {}", e),
            )
        })?
        .into_iter()
        .map(|row| Todo {
            id: row.get("id"),
            user_id: row.get("user_id"),
            title: row.get("title"),
            completed: row.get("completed"),
        })
        .collect::<Vec<_>>();

    Ok((StatusCode::OK, Json(items)))
}

async fn view_all_todos_by_id(
    Path(user_id): Path<i32>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let items = sqlx::query("SELECT user_id, id, title, completed FROM todos WHERE user_id = $1 AND is_deleted = FALSE ORDER BY id ASC")
        .bind(user_id)
        .fetch_all(&*state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch items: {}", e),
            )
        })?
        .into_iter()
        .map(|row| Todo {
            id: row.get("id"),
            user_id: row.get("user_id"),
            title: row.get("title"),
            completed: row.get("completed"),
        })
        .collect::<Vec<_>>();

    Ok((StatusCode::OK, Json(items)))
}

async fn create_todo(
    State(state): State<AppState>,
    Json(payload): Json<Todo>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let result = sqlx::query("INSERT INTO todos (user_id, title, completed, is_deleted) VALUES ($1, $2, $3, $4) RETURNING id")
        .bind(payload.user_id)
        .bind(payload.title)
        .bind(payload.completed)
        .bind(false)
        .fetch_one(&*state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to insert item: {}", e),
            )
        })?;

    let inserted_id: i32 = result.get("id");

    Ok((StatusCode::CREATED, Json(json!({ "id": inserted_id }))))
}

async fn update_todo(
    Path(id): Path<i32>,
    State(state): State<AppState>,
    Json(payload): Json<Todo>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let result = sqlx::query(
        "UPDATE todos SET title = $1, completed = $2 WHERE id = $3 AND is_deleted = FALSE",
    )
    .bind(payload.title)
    .bind(payload.completed)
    .bind(id)
    .execute(&*state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update item: {}", e),
        )
    })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Todo with id {} not found", id),
        ));
    }

    Ok((StatusCode::OK, "Todo updated successfully."))
}

async fn delete_todo(
    Path(id): Path<i32>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let result = sqlx::query("CALL delete_todo($1, $2)")
        .bind(id)
        .bind(false)
        .execute(&*state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to delete item: {}", e),
            )
        })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Todo with id {} not found", id),
        ));
    }

    Ok((StatusCode::OK, "Todo deleted successfully."))
}

async fn update_delete_status(
    Path(id): Path<i32>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let result = sqlx::query("UPDATE todos SET is_deleted = TRUE WHERE id = $1")
        .bind(id)
        .execute(&*state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to update delete status: {}", e),
            )
        })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Todo with id {} not found", id),
        ));
    }

    Ok((StatusCode::OK, "Table marked as deleted successfully."))
}

#[axum::debug_handler]
async fn register(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut form_fields = HashMap::new();
    let mut image_file_name = String::new();

    let minimum_password_length = 8;

    let now = chrono::Utc::now().naive_utc();

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Failed to read multipart field: {}", e),
        )
    })? {
        match field.name() {
            Some("profile_image") => {
                let file_name = field.file_name().unwrap_or("unknown").to_string();
                let content_type = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_string();
                let data = field.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read file data: {}", e),
                    )
                })?;
                // Here you would typically save the file to storage or database
                println!(
                    "Received file: {} (type: {}, size: {} bytes)",
                    file_name,
                    content_type,
                    data.len()
                );

                image_file_name = upload_image_to_cloud(file_name, data.to_vec(), "image-uploads")
                    .await
                    .map_err(|e| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to upload image: {}", e),
                        )
                    })?;
            }
            _ => {
                let name = field.name().unwrap_or("").to_string();
                let value = field.text().await.map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Failed to read field value: {}", e),
                    )
                })?;
                form_fields.insert(name, value);
            }
        }
    }

    let information = RegistrationRequest {
        id: None,
        username: form_fields.get("username").cloned().unwrap_or_default(),
        first_name: form_fields.get("first_name").cloned().unwrap_or_default(),
        middle_name: form_fields.get("middle_name").cloned(),
        last_name: form_fields.get("last_name").cloned().unwrap_or_default(),
        email: form_fields.get("email").cloned().unwrap_or_default(),
        email_verified: form_fields
            .get("email_verified")
            .map(|v| v == "true")
            .unwrap_or(false),
        email_verified_at: None,
        birthday: form_fields
            .get("birthday")
            .and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok()),
        created_at: now,
        updated_at: now,
        image: if image_file_name.is_empty() {
            None
        } else {
            Some(image_file_name)
        },
        role_type: form_fields
            .get("role_type")
            .cloned()
            .unwrap_or_else(|| "user".to_string()),
    };

    let info_errors = validate_information(&information);
    if let Err(errors) = info_errors {
        return Err((StatusCode::BAD_REQUEST, errors));
    }

    if !form_fields.contains_key("password") || form_fields.get("password").unwrap().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Password is required".to_string()));
    }

    if form_fields.get("password").unwrap().len() < minimum_password_length {
        return Err((
            StatusCode::BAD_REQUEST,
            "Password must be at least 8 characters long".to_string(),
        ));
    }

    state
        .db
        .execute(
            sqlx::query("CALL insert_information($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)")
                .bind(&information.username)
                .bind(&information.first_name)
                .bind(&information.middle_name)
                .bind(&information.last_name)
                .bind(&information.email)
                .bind(information.birthday)
                .bind(information.created_at)
                .bind(information.updated_at)
                .bind(&information.role_type)
                .bind(&information.image),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to insert user: {}", e),
            )
        })?;

    let row = state
        .db
        .fetch_one(
            sqlx::query("SELECT id, email FROM tbl_information WHERE username = ?")
                .bind(&information.username),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch user after insertion: {}", e),
            )
        })?;
    let id: i32 = row.get("id");
    let email: String = row.get("email");

    let mut credentials = UserCredentials {
        id: None,
        user_id: id,
        username: information.username.clone(),
        password: hash_password(form_fields.get("password").unwrap().to_string()).await,
        jwt_token: None,
        active_session: true,
        active_session_deleted: false,
        created_at: now,
        updated_at: now,
    };

    //credentials blank checks
    if (credentials.username).trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Username is required".to_string()));
    }

    if (credentials.password).trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Password is required".to_string()));
    }

    //credentials sanitization
    let sanitization_regex = Regex::new(r"<[^>]*>").unwrap();
    credentials.username = sanitization_regex
        .replace_all(&credentials.username, "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#x27;")
        .replace("'", "&#x27;")
        .replace("/", "&#x2F;");

    if (credentials.jwt_token).is_some() {
        credentials.jwt_token = Some(
            sanitization_regex
                .replace_all(&credentials.jwt_token.clone().unwrap(), "")
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;"),
        );
    }

    //credentials validation
    if credentials.password.len() < minimum_password_length {
        return Err((
            StatusCode::BAD_REQUEST,
            "Password must be at least 8 characters long".to_string(),
        ));
    }

    let password_regex =
        Regex::new(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$")
            .unwrap();
    if !password_regex
        .is_match(&credentials.password)
        .unwrap_or(false)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character".to_string(),
        ));
    }

    let username_regex = Regex::new(r"^[a-zA-Z0-9_]+$").unwrap();
    if !username_regex
        .is_match(&credentials.username)
        .unwrap_or(false)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Username must be at least 3 characters long and can only contain letters, numbers, dots, hyphens, or underscores".to_string(),
        ));
    }

    state
        .db
        .execute(
            sqlx::query("CALL insert_credentials($1, $2, $3, $4)")
                .bind(credentials.user_id)
                .bind(&credentials.username)
                .bind(&credentials.password)
                .bind(credentials.created_at),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to insert credentials: {}", e),
            )
        })?;

    let verification_link = format!("http://localhost:3000/api/user/email/verify?user_id={}", id);

    let email_logs = EmailVerification {
        user_id: id,
        from_system: EmailVerificationSource::Registration,
        sender_email: env::var("GMAIL_EMAIL").unwrap_or_else(|_| "".to_string()),
        receiver_email: email,
        subject: format!(
            "Email Verification for Registration: {}",
            information.first_name
        ),
        body: format!(
            r#"
            Hello {},

            Your registration was successful!

            Please verify your email by clicking the link below:
            {}

            Best regards,
            The Dr. Fate Team
        "#,
            information.first_name, verification_link
        ),
        status: "pending".to_string(),
        requested_at: now,
        verified_at: None,
    };

    let access_token = get_gmail_access_token().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get Gmail access token: {}", e),
        )
    })?;

    send_verification_email(&email_logs, &access_token, &state)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to send verification email: {}", e),
            )
        })?;

    Ok((
        StatusCode::OK,
        "Registration successful. Please check your email for verification.",
    ))
}

async fn verify_email(
    query: Query<HashMap<String, String>>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user_id = query.get("user_id").and_then(|v| v.parse::<i32>().ok());
    if user_id.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "User ID was not passed successfully".to_string(),
        ));
    }

    let date_now = chrono::Utc::now().naive_utc();
    let user_id = user_id.unwrap();
    let status = "verified";

    state
        .db
        .execute(
            sqlx::query(
                "UPDATE tbl_email_sending SET status = $1, verified_at = $2 WHERE user_id = $3",
            )
            .bind(status)
            .bind(date_now)
            .bind(user_id),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to update user: {}", e),
            )
        })?;

    Ok((StatusCode::OK, "Email verified successfully"))
}

async fn upload_image_to_cloud(
    file_name: String,
    data: Vec<u8>,
    bucket: &str,
) -> Result<String, String> {
    let allowed_extensions = ["png", "jpg", "jpeg", "gif"];
    let file_extension = file_name
        .split('.')
        .next_back()
        .unwrap_or("")
        .to_lowercase();
    if !allowed_extensions.contains(&file_extension.as_str()) {
        return Err("Unsupported file type".to_string());
    }
    let filename = format!("{}.{}", Uuid::new_v4(), file_extension);
    let supabase_url = env::var("SUPABASE_URL").expect("SUPABASE_URL is not set");
    let supabase_key =
        env::var("SUPABASE_SERVICE_ROLE_KEY").expect("SUPABASE_SERVICE_ROLE_KEY is not set");

    let response = reqwest::Client::new()
        .put(format!(
            "https://{}/storage/v1/object/{}/{}",
            supabase_url, bucket, filename
        ))
        .body(data)
        .bearer_auth(supabase_key)
        .send()
        .await
        .map_err(|e| format!("Failed to upload to Supabase: {}", e))?;

    if (response.status() != reqwest::StatusCode::OK)
        && (response.status() != reqwest::StatusCode::CREATED)
    {
        return Err(format!(
            "Failed to upload image, status: {}",
            response.status()
        ));
    }

    Ok(filename)
}

fn validate_information(info: &RegistrationRequest) -> Result<(), String> {
    let mut errors = Vec::new();
    let name_regex = Regex::new(r"^[a-zA-Z]+(([',. -][a-zA-Z ])?[a-zA-Z]*)*$").unwrap();
    let username_regex = Regex::new(r"^[a-zA-Z0-9._-]{3,}$").unwrap();

    if info.username.trim().is_empty() {
        errors.push("Username is required");
    }
    if !username_regex.is_match(&info.username).unwrap_or(false) {
        errors.push("Username must be at least 3 characters long and can only contain letters, numbers, dots, underscores, and hyphens");
    }

    if info.first_name.trim().is_empty() {
        errors.push("First name is required");
    }
    if !name_regex.is_match(&info.first_name).unwrap_or(false) {
        errors.push("First name is not valid");
    }
    if let Some(middle_name) = &info.middle_name
        && !middle_name.trim().is_empty()
        && !name_regex.is_match(middle_name).unwrap_or(false)
    {
        errors.push("Middle name is not valid");
    }

    if info.last_name.trim().is_empty() {
        errors.push("Last name is required");
    }

    if !name_regex.is_match(&info.last_name).unwrap_or(false) {
        errors.push("Last name is not valid");
    }

    if info.email.trim().is_empty() {
        errors.push("Email is required");
    }

    if !info.email.contains('@') || !info.email.contains('.') {
        errors.push("Email is not valid");
    }

    if info.role_type.trim().is_empty() {
        errors.push("Role type is required");
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(", "))
    }
}

async fn send_verification_email(
    email_logs: &EmailVerification,
    access_token: &str,
    state: &AppState,
) -> Result<(), String> {
    let user_email = env::var("GMAIL_EMAIL").expect("GMAIL_EMAIL is not set");

    // let email: ! = lettre::Message::builder()
    //     .from(user_email.parse().unwrap())
    //     .to(email_logs.receiver_email.parse().unwrap())
    //     .subject(email_logs.subject.clone())
    //     .header(lettre::message::header::ContentType::TEXT_HTML)
    //     .body(email_logs.body.to_string())
    //     .map_err(|e| format!("Failed to build email: {}", e))?;

    // //consider using lettre::AsyncSmtpTransport::starttls_relay for better security if your SMTP server supports it
    // let mailer = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay("smtp.gmail.com")
    //     .map_err(|e| format!("Failed to create SMTP transport: {}", e))?
    //     .credentials(lettre::transport::smtp::authentication::Credentials::new(
    //         user_email,
    //         access_token.to_string(),
    //     ))
    //     .build();

    // mailer
    //     .send(email)
    //     .await
    //     .map_err(|e| format!("Failed to send email: {}", e))?;

    let email = MessageBuilder::new()
        .from(user_email.clone())
        .to(email_logs.receiver_email.clone())
        .subject(email_logs.subject.clone())
        .text_body(email_logs.body.clone())
        .into_message()
        .map_err(|e| format!("Failed to build email: {}", e))?;

    let mailer: SmtpMailer = SmtpMailer::new(
        "smtp.gmail.com".into(),
        587,
        async_mailer::SmtpInvalidCertsPolicy::Deny,
        user_email.clone(),
        async_mailer::SecretString::from(access_token),
    );

    mailer
        .send_mail(email)
        .await
        .map_err(|e| format!("Failed to build email: {}", e))?;

    let result = state
        .db
        .execute(
            sqlx::query("CALL insert_email_sending($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)")
                .bind(email_logs.user_id)
                .bind(email_logs.from_system.to_string())
                .bind(email_logs.sender_email.clone())
                .bind(email_logs.receiver_email.clone())
                .bind(email_logs.status.clone())
                .bind(email_logs.subject.clone())
                .bind(email_logs.body.clone())
                .bind(email_logs.requested_at)
                .bind(email_logs.verified_at),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to insert email logs: {}", e),
            )
        })
        .unwrap();

    if result.rows_affected() == 0 {
        return Err("Failed to log email sending".to_string());
    }

    Ok(())
}

async fn get_gmail_access_token() -> Result<String, String> {
    let client_id =
        env::var("GMAIL_CLIENT_ID").map_err(|_| "GMAIL_CLIENT_ID is not set".to_string())?;
    let client_secret = env::var("GMAIL_CLIENT_SECRET")
        .map_err(|_| "GMAIL_CLIENT_SECRET is not set".to_string())?;
    let refresh_token = env::var("GMAIL_REFRESH_TOKEN")
        .map_err(|_| "GMAIL_REFRESH_TOKEN is not set".to_string())?;

    let params = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("refresh_token", refresh_token.as_str()),
        ("grant_type", "refresh_token"),
    ];

    let client = reqwest::Client::new();
    let res = client
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {}", e))?;

    if !res.status().is_success() {
        return Err(format!(
            "Failed to get access token, status: {}",
            res.status()
        ));
    }

    let json: serde_json::Value = res
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    let access_token = json
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "access_token not found in response".to_string())?;

    Ok(access_token.to_string())
}

async fn hash_password(password: String) -> String {
    let argon2 = Argon2::default(); //uses Argon2id instead of Argon2i, with default arguments and parameters

    // let params = Params::new(65536, 2, 1, None).unwrap(); // memory size in KB, iterations, parallelism, output length

    // let argon2 = Argon2::new(
    //     argon2::Algorithm::Argon2i,      //algorithm
    //     argon2::Version::V0x13,  // version, not sure which one was used in the original
    //     params,      // parameters
    // );

    let mut output_password: Vec<u8> = vec![0u8; 32]; // 32 bytes output for Argon2
    argon2
        .hash_password_into(password.as_bytes(), &[], &mut output_password)
        .unwrap();
    output_password
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

async fn login(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let username = payload.username;
    let password = payload.password;

    let browser_info = headers
        .get("User-Agent")
        .ok_or((StatusCode::BAD_REQUEST, "Missing User-Agent header".into()))?
        .to_str()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid User-Agent header".into()))?;

    let ip_address = headers
        .get("X-Forwarded-For")
        .ok_or((StatusCode::BAD_REQUEST, "Missing X-Forwarded-For header".into()))?
        .to_str()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid X-Forwarded-For header".into()))?;

    // unimplemented!("Validation for login data");

    let (user_id, hashed_password) = get_user_id_and_hashed_password(username.clone(), &state)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid credentials".into()))?;

    if !verify_password(password.clone(), hashed_password.clone()).await {
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".into()));
    }

    if !check_email_status(user_id, &state)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
        .unwrap()
    {
        return Err((StatusCode::UNAUTHORIZED, "Email not verified".into()));
    }

    //Generate JWT and session
    let jwt_token = generate_jwt(user_id).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let session_id = Uuid::new_v4().to_string(); //different from the original implementation of 16-length byte random string

    let session_deleted = false;

    update_session(
        user_id,
        session_id.clone(),
        jwt_token.clone(),
        session_deleted,
        &state,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Log the login attempt
    insert_audit_log(user_id, browser_info, &state)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    println!("User {} logged in from IP: {}, Browser: {}", user_id, ip_address, browser_info);

    Ok(Json(LoginResponse {
        user_id,
        username,
        jwt_token,
        active_session: session_id,
        active_session_deleted: session_deleted,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
   user_id: i32,
   iat: usize,
}

async fn generate_jwt(user_id: i32) -> Result<String, String> {
    // let secret_key = env::var("JWT_SECRET").map_err(|_| "JWT_SECRET env var must be set")?;
    // let secret_key = secret_key.as_bytes();
    // let expiration = chrono::Utc::now()
    //     .checked_add_signed(chrono::Duration::hours(24))
    //     .ok_or("Invalid expiration time")?
    //     .timestamp();
    // let claims = Claims {
    //     sub: user_id,
    //     exp: expiration as usize,
    // };
    // encode(&Header::default(), &claims, &EncodingKey::from_secret(secret_key))
    //     .map_err(|e| format!("Failed to generate JWT: {}", e))

    let secret_token = env::var("SECRET_TOKEN").map_err(|_| "SECRET_TOKEN env var must be set")?;

    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &Claims { user_id, iat: chrono::Utc::now().timestamp() as usize },
        &jsonwebtoken::EncodingKey::from_secret(secret_token.as_bytes()),
    )
    .map_err(|e| format!("Failed to generate JWT: {}", e))?;

    Ok(token)
}

async fn insert_audit_log(user_id: i32, browser_info: &str, state: &AppState) -> Result<(), String> {
    // let now = chrono::Utc::now().naive_utc();
    // let user_agent = user_agent_parser::UserAgentParser::new();
    // let parsed_ua = user_agent.parse(browser_info);

    // let browser = parsed_ua.family;
    // let os = parsed_ua.os.family;
    // let device = parsed_ua.device.family;

    // let ip_address = local_ipaddress::get().unwrap_or_else(|| "Unknown".to_string());

    // // Insert the audit log into the database
    // // Assuming you have a table named 'audit_logs' with appropriate columns
    // // Adjust the SQL query according to your actual table schema
    // // Here we just print the log for demonstration purposes

    // println!(
    //     "Audit Log - User ID: {}, IP Address: {}, Browser: {}, OS: {}, Device: {}, Timestamp: {}",
    //     user_id, ip_address, browser, os, device, now
    // );

    let now = chrono::Utc::now().naive_utc();
    let browser = browser_info.to_string();

    state
        .db
        .execute(
            sqlx::query("INSERT INTO audit_trail (user_id, timestamp, browser) VALUES (?, ?, ?) RETURNING id, user_id, timestamp, browser")
                .bind(user_id)
                .bind(now)
                .bind(browser),
        )
        .await
        .map_err(|e| format!("Failed to insert audit log: {}", e))?;

    Ok(())
}

async fn get_user_id_and_hashed_password(
    username: String,
    state: &AppState,
) -> Result<Option<(i32, String)>, String> {
    let row = state
        .db
        .fetch_optional(
            sqlx::query("SELECT user_id, password FROM tbl_credentials WHERE username = ?")
                .bind(username),
        )
        .await
        .map_err(|e| format!("Failed to fetch user: {}", e))?;

    if let Some(row) = row {
        let user_id: i32 = row.get("user_id");
        let hashed_password: String = row.get("password");
        Ok(Some((user_id, hashed_password)))
    } else {
        Ok(None)
    }
}

async fn check_email_status(user_id: i32, state: &AppState) -> Result<bool, String> {
    let email_logs: Option<String> = state
        .db
        .fetch_optional(
            sqlx::query("SELECT status FROM tbl_email_sending WHERE user_id = ?").bind(user_id),
        )
        .await
        .map_err(|e| format!("Failed to fetch email logs: {}", e))?
        .map(|row| row.get("status"));

    match email_logs {
        Some(log) => {
            if log == "verified" {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        None => Ok(false),
    }
}

async fn update_session(
    user_id: i32,
    session_id: String,
    jwt_token: String,
    session_deleted: bool,
    state: &AppState,
) -> Result<(), String> {
    state
        .db
        .execute(
            sqlx::query("UPDATE tbl_credentials SET active_session = $1, jwt_token = $2, active_session_deleted = $3 WHERE id = $4")
                .bind(session_id)
                .bind(jwt_token)
                .bind(session_deleted)
                .bind(user_id),
        )
        .await
        .map_err(|e| format!("Failed to update session: {}", e))?;
    Ok(())
}

async fn verify_password(password: String, hashed_password: String) -> bool {
    use argon2::PasswordHash;
    let argon2 = Argon2::default();

    let parsed_hash = match PasswordHash::new(&hashed_password) {
        Ok(hash) => hash,
        Err(_) => return false,
    };

    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

async fn retrieve_profile_image(
    Path(user_id): Path<i32>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let image_name: Option<String> = state
        .db
        .fetch_optional(
            sqlx::query("SELECT image FROM tbl_information WHERE id = ?").bind(user_id),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch user image: {}", e),
            )
        })?
        .map(|row| row.get("image"));

    if let Some(image_name) = image_name {
        if image_name.is_empty() {
            return Err((StatusCode::NOT_FOUND, "No profile image found".to_string()));
        }

        let supabase_url = env::var("SUPABASE_URL").expect("SUPABASE_URL is not set");
        let supabase_key =
            env::var("SUPABASE_SERVICE_ROLE_KEY").expect("SUPABASE_SERVICE_ROLE_KEY is not set");

        let response = reqwest::Client::new()
            .get(format!(
                "https://{}/storage/v1/object/public/image-uploads/{}",
                supabase_url, image_name
            ))
            .bearer_auth(supabase_key)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch image from Supabase: {}", e)).unwrap();

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err((StatusCode::NOT_FOUND, "Profile image not found".to_string()));
        }

        if !response.status().is_success() {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch image, status: {}", response.status()),
            ));
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        let bytes = response.bytes().await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to read image bytes: {}", e),
            )
        })?;

        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, content_type)],
            bytes,
        ))
    } else {
        Err((StatusCode::NOT_FOUND, "No profile image found".to_string()))
    }
}

async fn update_profile_image(
    Path(user_id): Path<i32>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let image_name: Option<String> = state
        .db
        .fetch_optional(
            sqlx::query("SELECT image FROM tbl_information WHERE id = ?").bind(user_id),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch user image: {}", e),
            )
        })?
        .map(|row| row.get("image"));

    if let Some(image_name) = image_name {
        let supabase_url = env::var("SUPABASE_URL").expect("SUPABASE_URL is not set");
        let supabase_key =
            env::var("SUPABASE_SERVICE_ROLE_KEY").expect("SUPABASE_SERVICE_ROLE_KEY is not set");
        let response = reqwest::Client::new()
            .delete(format!(
                "https://{}/storage/v1/object/image-uploads/{}",
                supabase_url, image_name
            ))
            .bearer_auth(supabase_key)
            .send()
            .await
            .map_err(|e| format!("Failed to delete image from Supabase: {}", e
            )).unwrap();
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err((StatusCode::NOT_FOUND, "Profile image not found".to_string()));
        }
        if !response.status().is_success() {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to delete image, status: {}", response.status()),
            ));
        }
    }
    Ok(StatusCode::OK)
}

async fn logout(
    Path(user_id): Path<i32>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let result = state
        .db
        .execute(
            sqlx::query(
                "UPDATE tbl_credentials SET active_session = FALSE, jwt_token = NULL, active_session_deleted = TRUE WHERE user_id = ?",
            )
            .bind(user_id),
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to logout user: {}", e),
            )
        })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            format!("User with id {} not found", user_id),
        ));
    }

    Ok((StatusCode::OK, "User logged out successfully"))
}

async fn audit_user(
    Path(user_id): Path<i32>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let result = state
        .db
        .fetch_all(sqlx::query("SELECT * FROM audit_trail WHERE user_id = $1 ORDER BY timestamp DESC").bind(user_id))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to audit user: {}", e),
            )
        })?;

    if result.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("User with id {} not found", user_id),
        ));
    }

    Ok((StatusCode::OK, "User audited successfully"))
}