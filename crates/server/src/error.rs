//! Unified error type for REST + gRPC handlers. REST converts via
//! [`IntoResponse`]; gRPC converts via [`Into<tonic::Status>`].
//!
//! The error body mirrors `axum::Json<{error: "...", detail?: "..."}>`
//! so consumers can match on the error tag without parsing the
//! human-readable detail string.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("internal error: {0}")]
    Internal(String),

    /// Stable-coded error from the spec §15.3 registry. Used by routes
    /// whose contract specifies error codes from a fixed vocabulary
    /// (e.g. the quote surface's `quote_not_found`,
    /// `quote_hash_mismatch`, `storage_unavailable`). The tag is the
    /// stable code; the HTTP status is whatever the caller picks for
    /// the family the code belongs to.
    #[error("{tag}: {detail}")]
    Coded {
        status: StatusCode,
        tag: &'static str,
        detail: String,
    },

    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }
    pub fn service_unavailable(msg: impl Into<String>) -> Self {
        Self::ServiceUnavailable(msg.into())
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Build a stable-coded error with a caller-chosen HTTP status.
    /// Used by routes whose contract pins a specific error tag onto a
    /// specific HTTP status code (e.g. quote_not_found → 404,
    /// quote_hash_mismatch → 500). Spec §15.3.
    pub fn coded(status: StatusCode, tag: &'static str, detail: impl Into<String>) -> Self {
        Self::Coded {
            status,
            tag,
            detail: detail.into(),
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Coded { status, .. } => *status,
            ApiError::Sqlx(_) | ApiError::Anyhow(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn tag(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::NotFound(_) => "not_found",
            ApiError::ServiceUnavailable(_) => "service_unavailable",
            ApiError::Internal(_) => "internal",
            ApiError::Coded { tag, .. } => tag,
            ApiError::Sqlx(_) | ApiError::Anyhow(_) => "internal",
        }
    }

    fn detail(&self) -> String {
        match self {
            ApiError::BadRequest(d)
            | ApiError::NotFound(d)
            | ApiError::ServiceUnavailable(d)
            | ApiError::Internal(d) => d.clone(),
            ApiError::Coded { detail, .. } => detail.clone(),
            ApiError::Sqlx(e) => format!("{e}"),
            ApiError::Anyhow(e) => format!("{e}"),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    detail: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.http_status();
        let body = ErrorBody {
            error: self.tag(),
            detail: self.detail(),
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "handler returned internal error");
        }
        (status, Json(body)).into_response()
    }
}

impl From<ApiError> for tonic::Status {
    fn from(err: ApiError) -> Self {
        let detail = err.detail();
        match err {
            ApiError::BadRequest(_) => tonic::Status::invalid_argument(detail),
            ApiError::NotFound(_) => tonic::Status::not_found(detail),
            ApiError::ServiceUnavailable(_) => tonic::Status::unavailable(detail),
            ApiError::Coded { status, .. } => match status {
                StatusCode::BAD_REQUEST => tonic::Status::invalid_argument(detail),
                StatusCode::NOT_FOUND => tonic::Status::not_found(detail),
                StatusCode::SERVICE_UNAVAILABLE => tonic::Status::unavailable(detail),
                _ => tonic::Status::internal(detail),
            },
            ApiError::Internal(_) | ApiError::Sqlx(_) | ApiError::Anyhow(_) => {
                tonic::Status::internal(detail)
            }
        }
    }
}
