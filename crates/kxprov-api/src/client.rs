use crate::{RequestBody, RequestEnvelope, Response, ResponseResult};
use std::path::Path;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("api {code}: {message}")]
    Remote { code: String, message: String },
    #[error("unexpected response")]
    Unexpected,
}

pub struct ApiClient {
    write: tokio::net::unix::OwnedWriteHalf,
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    next_id: u64,
}

impl ApiClient {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, ApiError> {
        let stream = UnixStream::connect(path).await?;
        let (read, write) = stream.into_split();
        Ok(Self {
            write,
            reader: BufReader::new(read),
            next_id: 1,
        })
    }

    pub async fn call(&mut self, body: RequestBody) -> Result<ResponseResult, ApiError> {
        let id = format!("{}", self.next_id);
        self.next_id += 1;
        let env = RequestEnvelope {
            id: id.clone(),
            body,
        };
        let line = serde_json::to_string(&env)?;
        self.write.write_all(line.as_bytes()).await?;
        self.write.write_all(b"\n").await?;
        self.write.flush().await?;

        let mut buf = String::new();
        self.reader.read_line(&mut buf).await?;
        let resp: Response = serde_json::from_str(buf.trim())?;
        if resp.id != id {
            return Err(ApiError::Unexpected);
        }
        resp.into_result().map_err(|e| ApiError::Remote {
            code: e.code,
            message: e.message,
        })
    }
}
