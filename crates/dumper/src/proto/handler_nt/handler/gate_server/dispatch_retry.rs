//! Bounded transport retry policy. Diagnostics contain fixed classifications
//! and numeric status only; response text, URLs, dispatch seeds and keys stay out.
use std::{io::ErrorKind, time::Duration, time::Instant};

use super::super::decoder::DecodeError;

const MAX_ATTEMPTS: usize = 3;
const DELAYS: [Duration; MAX_ATTEMPTS - 1] =
    [Duration::from_millis(150), Duration::from_millis(450)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Failure {
    pub(super) stage: &'static str,
    pub(super) reason: &'static str,
    pub(super) retryable: bool,
    pub(super) code: Option<u32>,
}

impl Failure {
    pub(super) fn http(stage: &'static str, error: &ureq::Error) -> Self {
        let (reason, retryable, code) = match error {
            ureq::Error::Timeout(_) => ("timeout", true, None),
            ureq::Error::HostNotFound => ("host-not-found", true, None),
            ureq::Error::ConnectionFailed => ("connection-failed", true, None),
            ureq::Error::StatusCode(status) => (
                "http-status",
                matches!(*status, 408 | 429 | 502 | 503 | 504),
                Some(u32::from(*status)),
            ),
            ureq::Error::Io(error) => match error.kind() {
                ErrorKind::TimedOut => ("io-timeout", true, None),
                ErrorKind::UnexpectedEof => ("io-truncated", true, None),
                ErrorKind::ConnectionReset => ("connection-reset", true, None),
                ErrorKind::ConnectionAborted => ("connection-aborted", true, None),
                ErrorKind::ConnectionRefused => ("connection-refused", true, None),
                ErrorKind::BrokenPipe => ("broken-pipe", true, None),
                ErrorKind::NotConnected => ("not-connected", true, None),
                ErrorKind::Interrupted => ("io-interrupted", true, None),
                ErrorKind::WouldBlock => ("io-would-block", true, None),
                _ => ("non-transient-io", false, None),
            },
            ureq::Error::BadUri(_) => ("invalid-uri", false, None),
            ureq::Error::InvalidProxyUrl => ("invalid-proxy", false, None),
            ureq::Error::Tls(_) | ureq::Error::Rustls(_) => ("tls-failure", false, None),
            ureq::Error::BodyExceedsLimit(_) => ("response-limit", false, None),
            ureq::Error::Protocol(_) => ("http-protocol", false, None),
            _ => ("non-transient-http", false, None),
        };
        Self {
            stage,
            reason,
            retryable,
            code,
        }
    }

    pub(super) fn base64(error: &base64::DecodeError) -> Self {
        let (reason, retryable) = match error {
            base64::DecodeError::InvalidLength(_) => ("base64-length", true),
            base64::DecodeError::InvalidPadding => ("base64-padding", true),
            // The base64 library explicitly identifies a nonsensical final
            // symbol as corruption/truncation; retry the original GET only.
            base64::DecodeError::InvalidLastSymbol(_, _) => ("base64-last-symbol", true),
            base64::DecodeError::InvalidByte(_, _) => ("base64-invalid-byte", false),
        };
        Self {
            stage: "base64",
            reason,
            retryable,
            code: None,
        }
    }

    pub(super) fn wire(error: &DecodeError) -> Self {
        let (reason, retryable) = match error {
            DecodeError::InvalidMemoryAccess => ("wire-truncated", true),
            DecodeError::UnsupportedWireType(_) => ("wire-unsupported-type", false),
        };
        Self {
            stage: "wire-decode",
            reason,
            retryable,
            code: None,
        }
    }

    pub(super) fn semantic(reason: &'static str, code: Option<u32>) -> Self {
        Self {
            stage: "dispatch-semantic",
            reason,
            retryable: false,
            code,
        }
    }
}

pub(super) fn run<T>(
    endpoint: &'static str,
    attempt: impl FnMut() -> Result<T, Failure>,
) -> Option<T> {
    run_with_wait(endpoint, attempt, std::thread::sleep)
}

fn run_with_wait<T>(
    endpoint: &'static str,
    mut attempt: impl FnMut() -> Result<T, Failure>,
    mut wait: impl FnMut(Duration),
) -> Option<T> {
    let started = Instant::now();
    for index in 0..MAX_ATTEMPTS {
        match attempt() {
            Ok(result) => {
                log::info!(
                    "[Gateway] fetch complete: endpoint={endpoint} attempts={} retries={} elapsed_ms={}",
                    index + 1,
                    index,
                    started.elapsed().as_millis()
                );
                return Some(result);
            }
            Err(failure) => {
                let delay = DELAYS.get(index).filter(|_| failure.retryable);
                if let Some(&delay) = delay {
                    // At most two detail records for each endpoint, followed
                    // by one final summary; no network error Display text.
                    log::debug!(
                        "[Gateway] fetch retry: endpoint={endpoint} attempt={} stage={} reason={} code={:?} delay_ms={}",
                        index + 1,
                        failure.stage,
                        failure.reason,
                        failure.code,
                        delay.as_millis()
                    );
                    wait(delay);
                } else {
                    log::warn!(
                        "[Gateway] fetch failed: endpoint={endpoint} attempts={} stage={} reason={} code={:?} retryable={} exhausted={} elapsed_ms={}",
                        index + 1,
                        failure.stage,
                        failure.reason,
                        failure.code,
                        failure.retryable,
                        failure.retryable && index + 1 == MAX_ATTEMPTS,
                        started.elapsed().as_millis()
                    );
                    return None;
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_failure_is_retried_then_success_is_returned() {
        let mut attempts = 0;
        let mut delays = Vec::new();
        let result = run_with_wait(
            "test",
            || {
                attempts += 1;
                if attempts < 3 {
                    Err(Failure::http(
                        "http-request",
                        &ureq::Error::Timeout(ureq::Timeout::Global),
                    ))
                } else {
                    Ok(7)
                }
            },
            |delay| delays.push(delay),
        );
        assert_eq!(result, Some(7));
        assert_eq!(attempts, MAX_ATTEMPTS);
        assert_eq!(delays, DELAYS);
    }

    #[test]
    fn retry_exhaustion_remains_failure_and_is_bounded() {
        let truncated = super::super::super::decoder::Decoder::new(vec![0x0a, 3, 1])
            .decode()
            .unwrap_err();
        assert!(matches!(truncated, DecodeError::InvalidMemoryAccess));
        let mut attempts = 0;
        let mut delays = Vec::new();
        let result: Option<()> = run_with_wait(
            "test",
            || {
                attempts += 1;
                Err(Failure::wire(&truncated))
            },
            |delay| delays.push(delay),
        );
        assert_eq!(result, None);
        assert_eq!(attempts, MAX_ATTEMPTS);
        assert_eq!(delays, DELAYS);
    }

    #[test]
    fn explicit_refusal_or_permanent_transport_error_is_not_retried() {
        for failure in [
            Failure::http("http-request", &ureq::Error::StatusCode(403)),
            Failure::http("http-request", &ureq::Error::BadUri("redacted".into())),
            Failure::wire(&DecodeError::UnsupportedWireType(3)),
            Failure::semantic("dispatch-retcode", Some(7)),
        ] {
            let mut attempts = 0;
            let result: Option<()> = run_with_wait(
                "test",
                || {
                    attempts += 1;
                    Err(failure)
                },
                |_| panic!("permanent failure must not schedule retry"),
            );
            assert_eq!(result, None);
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn only_selected_transient_status_codes_are_retried() {
        for status in [408, 429, 502, 503, 504] {
            let error = Failure::http("http-request", &ureq::Error::StatusCode(status));
            assert!(error.retryable);
            assert_eq!(error.code, Some(u32::from(status)));
        }
        for status in [400, 401, 403, 404, 422, 500, 501] {
            assert!(!Failure::http("http-request", &ureq::Error::StatusCode(status)).retryable);
        }
    }

    #[test]
    fn base64_truncation_and_invalid_content_have_distinct_policies() {
        use base64::Engine;
        let standard = base64::engine::general_purpose::STANDARD;
        for input in ["Y", "YQ", "YR=="] {
            let error = standard.decode(input).unwrap_err();
            assert!(Failure::base64(&error).retryable);
        }
        let invalid = standard.decode("<html>").unwrap_err();
        assert!(!Failure::base64(&invalid).retryable);
    }

    #[test]
    fn truncated_body_io_retries_but_invalid_data_and_body_limits_do_not() {
        for kind in [ErrorKind::UnexpectedEof, ErrorKind::ConnectionReset] {
            assert!(Failure::http("http-body", &ureq::Error::Io(kind.into())).retryable);
        }
        for kind in [ErrorKind::InvalidData, ErrorKind::PermissionDenied] {
            assert!(!Failure::http("http-body", &ureq::Error::Io(kind.into())).retryable);
        }
        assert!(
            !Failure::http(
                "http-body",
                &ureq::Error::BodyExceedsLimit(10 * 1024 * 1024)
            )
            .retryable
        );
    }
}
