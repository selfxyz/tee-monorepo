use anyhow::{anyhow, Context};
use serde_json::json;
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};
use warp::{http::Method, Filter};

use crate::logging::log_message;

pub async fn fetch_logs_with_offset(
    enclave_log_file_path: &str,
    log_id: u64,
    offset: usize,
) -> anyhow::Result<Vec<String>> {
    let start_log_id = if log_id > offset as u64 {
        log_id - offset as u64
    } else {
        1
    };

    let file = File::open(enclave_log_file_path)
        .await
        .context("http server: failed to open enclave log file")?;
    let mut reader = BufReader::new(file).lines();
    let mut logs: Vec<String> = Vec::with_capacity(offset);

    while let Some(line) = reader.next_line().await? {
        let Some((log_id_str, message)) = line.split_once("] ") else {
            return Err(anyhow!("Error"));
        };
        let log_id_str = log_id_str.trim_start_matches('[');
        let current_log_id = log_id_str
            .parse::<u64>()
            .context("failed to parse log id")?;
        if current_log_id >= start_log_id {
            let log_entry = format!("[{}] {}", current_log_id, message);
            logs.push(log_entry);
        }
        if logs.len() >= offset {
            break;
        }
    }

    Ok(logs)
}

pub fn create_routes(
    enclave_logs: String,
    script_logs: String,
    log_counter: Arc<AtomicU64>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let logs_file = enclave_logs.clone();
    let log_counter1 = log_counter.clone();
    let log_counter2 = log_counter.clone();
    let home_html = include_str!("../assets/logs.html");

    let home_route = warp::path("logs")
        .and(warp::get())
        .map(move || warp::reply::html(home_html));

    let tail_log_route = warp::path("logs")
        .and(warp::path("tail-log-id"))
        .and(warp::get())
        .and_then(move || {
            let log_counter = log_counter1.clone();
            async move {
                let latest_log_id = log_counter.load(Ordering::Relaxed);
                Ok::<_, Infallible>(warp::reply::json(&json!({"log_id": latest_log_id})))
            }
        });

    let history_route = warp::path("logs")
        .and(warp::path("history"))
        .and(warp::query::<HashMap<String, String>>())
        .and_then(move |params: HashMap<String, String>| {
            let logs_file = logs_file.clone();
            let log_counter = log_counter2.clone();
            async move {
                let latest_log_id = log_counter.load(Ordering::Relaxed);
                let log_id = params
                    .get("log_id")
                    .and_then(|id| id.parse::<u64>().ok())
                    .unwrap_or(latest_log_id);

                let offset = params
                    .get("offset")
                    .and_then(|off| off.parse::<usize>().ok())
                    .unwrap_or(10);

                let result = fetch_logs_with_offset(&logs_file, log_id, offset).await;

                let response = match result {
                    Ok(logs) => warp::reply::json(&logs),
                    Err(err) => {
                        let _ = log_message(
                            &logs_file,
                            &err.context("failed to fetch logs with offset").to_string(),
                        )
                        .await;
                        warp::reply::json(&json!({"error": "Failed to retrieve logs."}))
                    }
                };

                Ok::<_, Infallible>(response)
            }
        });

    let sse_route = warp::path("logs")
        .and(warp::path("stream"))
        .and(warp::query::<HashMap<String, String>>())
        .and(warp::get())
        .map(move |params: HashMap<String, String>| {
            let logs_file = enclave_logs.to_string();
            let script_logs = script_logs.to_string();
            let log_counter = log_counter.clone();

            let start_from = params
                .get("start_from")
                .and_then(|id| id.parse::<u64>().ok())
                .unwrap_or_else(|| log_counter.load(Ordering::Relaxed));

            let stream = async_stream::stream! {
                loop {  // Outer loop for retrying on errors
                    match File::open(&logs_file).await {
                        Ok(file) => {
                            let mut reader = BufReader::new(file);
                            let mut line = String::new();

                            // Skip to start_from line if needed
                            let mut current_line = 1;
                            while current_line < start_from {
                                match reader.read_line(&mut line).await {
                                    Ok(0) => break,  // EOF
                                    Ok(_) => {
                                        current_line += 1;
                                        line.clear();
                                    },
                                    Err(e) => {
                                        let _ = log_message(&script_logs, &format!("Error skipping lines: {}", e)).await;
                                        break;
                                    }
                                }
                            }

                            // Stream from the current position
                            loop {
                                match reader.read_line(&mut line).await {
                                    Ok(0) => {
                                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                                    }
                                    Ok(_) => {
                                        if !line.is_empty() {
                                            yield Ok::<_, warp::Error>(warp::sse::Event::default().data(line.clone()));
                                            line.clear();
                                        }
                                    }
                                    Err(e) => {
                                        let _ = log_message(&script_logs, &format!("Error reading line: {}", e)).await;
                                        break;  // Break inner loop to retry
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let _ = log_message(&script_logs, &format!("Error opening log file: {}", e)).await;
                            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;  // Wait before retry
                        }
                    }
                }
            };
            warp::sse::reply(warp::sse::keep_alive().stream(stream))
        });

    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["*"])
        .allow_methods(vec![Method::GET]);

    history_route
        .or(tail_log_route)
        .or(sse_route)
        .or(home_route)
        .with(cors)
}
