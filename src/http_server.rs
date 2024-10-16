use anyhow::{anyhow, Context};
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fs::File;
use std::io::{BufRead, BufReader};
use warp::{http::Method, Filter};

use crate::logging::log_message;

pub fn fetch_logs_with_offset(
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
        .context("http server: failed to open enclave log file")?;
    let reader = BufReader::new(file);
    let mut logs: Vec<String> = Vec::with_capacity(offset);

    for line in reader.lines().map_while(Result::ok) {
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
    enclave_log_file_path: String,
    sse_tx: tokio::sync::broadcast::Sender<String>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let logs_file = enclave_log_file_path.clone();
    let home_html = include_str!("../assets/logs.html");

    let home_route = warp::path("logs")
        .and(warp::get())
        .map(move || warp::reply::html(home_html));

    let history_route = warp::path("logs")
        .and(warp::path("history"))
        .and(warp::query::<HashMap<String, String>>())
        .and_then(move |params: HashMap<String, String>| {
            let logs_file = logs_file.clone();
            async move {
                let log_id = params
                    .get("log_id")
                    .and_then(|id| id.parse::<u64>().ok())
                    .unwrap_or(1);

                let offset = params
                    .get("offset")
                    .and_then(|off| off.parse::<usize>().ok())
                    .unwrap_or(10);

                let response = fetch_logs_with_offset(&logs_file, log_id, offset).map_or_else(
                    |err| {
                        let _ = log_message(
                            &logs_file,
                            &err.context("failed to fetch logs with offset").to_string(),
                        );
                        warp::reply::json(&json!({"error": "Failed to retrieve logs."}))
                    },
                    |logs| warp::reply::json(&logs),
                );

                Ok::<_, Infallible>(response)
            }
        });

    let sse_route = warp::path("logs")
        .and(warp::path("stream"))
        .and(warp::get())
        .map(move || {
            let sse_rx = sse_tx.subscribe();
            let stream = async_stream::stream! {
                let mut sse_rx = sse_rx;
                while let Ok(msg) = sse_rx.recv().await {
                    yield Ok::<_, warp::Error>(warp::sse::Event::default().data(msg));
                }
            };
            warp::sse::reply(warp::sse::keep_alive().stream(stream))
        });

    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "Access-Control-Allow-Headers",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Origin",
            "Accept",
            "X-Requested-With",
            "Content-Type",
        ])
        .allow_methods(&[
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
            Method::HEAD,
        ]);

    history_route.or(sse_route).or(home_route).with(cors)
}
