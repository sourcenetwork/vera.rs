use serde_json::json;

#[cfg(any(target_os = "linux", test))]
const INPUT_LIMIT: usize = 4096;

#[cfg(any(target_os = "linux", test))]
fn parse_counters(input: &str) -> std::io::Result<[Option<u64>; 3]> {
    use std::io::{Error, ErrorKind};

    let invalid = || Error::new(ErrorKind::InvalidData, "invalid process I/O counters");
    if input.len() > INPUT_LIMIT {
        return Err(invalid());
    }
    let mut values = [None; 3];
    for line in input.lines() {
        let mut fields = line.split_whitespace();
        let index = match fields.next() {
            Some("read_bytes:") => 0,
            Some("write_bytes:") => 1,
            Some("cancelled_write_bytes:") => 2,
            _ => continue,
        };
        let number = fields.next().ok_or_else(invalid)?;
        if values[index].is_some()
            || !number.bytes().all(|byte| byte.is_ascii_digit())
            || fields.next().is_some()
        {
            return Err(invalid());
        }
        values[index] = Some(number.parse::<u64>().map_err(|_| invalid())?);
    }
    Ok(values)
}

#[cfg(target_os = "linux")]
async fn read_counters(pid: u32) -> std::io::Result<[Option<u64>; 3]> {
    use tokio::io::AsyncReadExt;

    let file = tokio::fs::File::open(format!("/proc/{pid}/io")).await?;
    let mut input = String::new();
    file.take((INPUT_LIMIT + 1) as u64)
        .read_to_string(&mut input)
        .await?;
    parse_counters(&input)
}

pub(super) async fn sample(pid: u32) -> serde_json::Value {
    #[cfg(target_os = "linux")]
    let (values, availability) =
        match tokio::time::timeout(std::time::Duration::from_secs(2), read_counters(pid)).await {
            Ok(Ok(values)) => {
                let availability = if values.iter().all(Option::is_some) {
                    "complete"
                } else {
                    "partial"
                };
                (values, availability)
            }
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::InvalidData => {
                ([None; 3], "invalid_data")
            }
            Ok(Err(_)) => ([None; 3], "read_error"),
            Err(_) => ([None; 3], "timed_out"),
        };
    #[cfg(not(target_os = "linux"))]
    let (values, availability) = ([None::<u64>; 3], "unsupported");
    json!({
        "pid": pid, "availability": availability,
        "read_bytes": values[0], "write_bytes": values[1],
        "cancelled_write_bytes": values[2],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_io_counters_preserve_zero_partial_and_full_width() {
        assert_eq!(
            parse_counters("rchar: 999\nread_bytes: 0\nwrite_bytes: 18446744073709551615\ncancelled_write_bytes: 4096\n").unwrap(),
            [Some(0), Some(u64::MAX), Some(4096)]
        );
        assert_eq!(
            parse_counters("write_bytes: 0\n").unwrap(),
            [None, Some(0), None]
        );
        assert_eq!(parse_counters("rchar: 100\n").unwrap(), [None; 3]);
    }

    #[test]
    fn process_io_counters_reject_ambiguous_or_unbounded_input() {
        for input in [
            "write_bytes:",
            "write_bytes: -1",
            "write_bytes: +1",
            "write_bytes: 1.5",
            "write_bytes: 1 B",
            "write_bytes: 0 extra",
            "write_bytes: 18446744073709551616",
            "read_bytes: 0\nread_bytes: 1",
        ] {
            assert_eq!(
                parse_counters(input).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
        }
        assert!(parse_counters(&" ".repeat(INPUT_LIMIT)).is_ok());
        assert!(parse_counters(&" ".repeat(INPUT_LIMIT + 1)).is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn process_io_reads_the_current_process() {
        let pid = std::process::id();
        let actual = sample(pid).await;
        assert_eq!(actual["pid"], pid);
        assert_eq!(actual["availability"], "complete");
        for field in ["read_bytes", "write_bytes", "cancelled_write_bytes"] {
            assert!(actual[field].as_u64().is_some(), "{field}");
        }
    }
}
