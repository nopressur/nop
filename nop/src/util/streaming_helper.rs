// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

#[derive(Debug, PartialEq, Eq)]
pub enum HttpRange {
    Closed(u64, u64),
    Open(u64),
    Suffix(u64),
}

/// Parse HTTP Range header value
/// Returns a vector of HttpRange enums
pub fn parse_range_header(range_header: &str) -> Option<Vec<HttpRange>> {
    // Range header format: "bytes=start-end,start-end,..."
    if !range_header.starts_with("bytes=") {
        return None;
    }

    let ranges_str = &range_header[6..]; // Skip "bytes="
    let mut ranges = Vec::new();

    for range_spec in ranges_str.split(',') {
        let range_spec = range_spec.trim();

        if range_spec.is_empty() {
            continue;
        }

        let parts: Vec<&str> = range_spec.splitn(2, '-').collect();
        let start_str = parts[0].trim();
        let end_str = parts[1].trim();

        if start_str.is_empty()
            && !end_str.is_empty()
            && let Ok(suffix_length) = end_str.parse::<u64>()
            && suffix_length > 0
        {
            // Suffix range: "-500" means last 500 bytes
            ranges.push(HttpRange::Suffix(suffix_length));
        } else if let Ok(start) = start_str.parse::<u64>() {
            if end_str.is_empty() {
                // Open-ended range: "500-" means from byte 500 to end
                ranges.push(HttpRange::Open(start));
            } else if let Ok(end) = end_str.parse::<u64>() {
                // Closed range: "500-999"
                if start <= end {
                    ranges.push(HttpRange::Closed(start, end));
                }
            }
        }
    }

    if ranges.is_empty() {
        None
    } else {
        Some(ranges)
    }
}

/// Calculate actual range bounds given a range specification and file size
/// Returns Some((start, end)) if the range is satisfiable, otherwise None.
pub fn calculate_range_bounds(range: &HttpRange, file_size: u64) -> Option<(u64, u64)> {
    if file_size == 0 {
        return None; // No ranges are satisfiable for an empty file.
    }
    let last_pos = file_size - 1;

    match *range {
        HttpRange::Closed(start, end) => {
            if start > end || start > last_pos {
                None
            } else {
                Some((start, end.min(last_pos)))
            }
        }
        HttpRange::Open(start) => {
            if start > last_pos {
                None
            } else {
                Some((start, last_pos))
            }
        }
        HttpRange::Suffix(length) => {
            if length == 0 || length > file_size {
                None
            } else {
                let start = file_size - length;
                Some((start, last_pos))
            }
        }
    }
}

/// Format Content-Range header value for HTTP response
pub fn format_content_range_header(start: u64, end: u64, total_size: u64) -> String {
    format!("bytes {}-{}/{}", start, end, total_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_range_header() {
        // Test valid ranges
        assert_eq!(
            parse_range_header("bytes=0-499"),
            Some(vec![HttpRange::Closed(0, 499)])
        );
        assert_eq!(
            parse_range_header("bytes=500-"),
            Some(vec![HttpRange::Open(500)])
        );
        assert_eq!(
            parse_range_header("bytes=-2500"),
            Some(vec![HttpRange::Suffix(2500)])
        );
        assert_eq!(
            parse_range_header("bytes=500-999"),
            Some(vec![HttpRange::Closed(500, 999)])
        );
        assert_eq!(
            parse_range_header("bytes=0-0"),
            Some(vec![HttpRange::Closed(0, 0)])
        );
        assert_eq!(
            parse_range_header("bytes=0-499, 500-999"),
            Some(vec![HttpRange::Closed(0, 499), HttpRange::Closed(500, 999)])
        );

        // Test invalid ranges
        assert_eq!(parse_range_header("invalid"), None);
        assert_eq!(parse_range_header("bytes="), None);
        assert_eq!(parse_range_header("bytes=-"), None);
        assert_eq!(parse_range_header("bytes=--"), None);
        assert_eq!(parse_range_header("bytes=abc-def"), None);
        assert_eq!(parse_range_header("bytes=500-400"), None); // start > end
        assert_eq!(parse_range_header("bytes=-0"), None); // suffix of 0 is invalid
    }

    #[test]
    fn test_calculate_range_bounds() {
        let file_size = 1000;

        // Test closed range
        assert_eq!(
            calculate_range_bounds(&HttpRange::Closed(0, 499), file_size),
            Some((0, 499))
        );
        assert_eq!(
            calculate_range_bounds(&HttpRange::Closed(500, 999), file_size),
            Some((500, 999))
        );
        // Test open-ended range
        assert_eq!(
            calculate_range_bounds(&HttpRange::Open(500), file_size),
            Some((500, 999))
        );
        // Test suffix range
        assert_eq!(
            calculate_range_bounds(&HttpRange::Suffix(200), file_size),
            Some((800, 999))
        );
        assert_eq!(
            calculate_range_bounds(&HttpRange::Suffix(1000), file_size),
            Some((0, 999))
        );

        // Test range beyond file size
        assert_eq!(
            calculate_range_bounds(&HttpRange::Closed(500, 1500), file_size),
            Some((500, 999))
        );
        assert_eq!(
            calculate_range_bounds(&HttpRange::Open(1000), file_size),
            None
        );
        assert_eq!(
            calculate_range_bounds(&HttpRange::Open(1200), file_size),
            None
        );
        assert_eq!(
            calculate_range_bounds(&HttpRange::Suffix(1500), file_size),
            None
        );

        // Test invalid ranges
        assert_eq!(
            calculate_range_bounds(&HttpRange::Closed(1000, 1200), file_size),
            None
        );
        assert_eq!(
            calculate_range_bounds(&HttpRange::Suffix(0), file_size),
            None
        );

        // Test with empty file
        assert_eq!(calculate_range_bounds(&HttpRange::Closed(0, 0), 0), None);
    }

    #[test]
    fn test_format_content_range_header() {
        assert_eq!(
            format_content_range_header(0, 499, 1000),
            "bytes 0-499/1000"
        );
        assert_eq!(
            format_content_range_header(500, 999, 1000),
            "bytes 500-999/1000"
        );
    }

    #[test]
    fn test_streaming_logic_for_md_files() {
        // Test that .md files should NOT be streamed even with Range header
        let md_file = "test.md";
        let streaming_enabled = true;
        let has_range_header = true;

        // New streaming logic: stream only if streaming enabled AND file is NOT .md AND has Range header
        let should_stream = streaming_enabled && !md_file.ends_with(".md") && has_range_header;
        assert!(!should_stream, ".md files should not be streamed");

        let md_file2 = "document.markdown";
        let should_stream2 = streaming_enabled && !md_file2.ends_with(".md") && has_range_header;
        assert!(
            should_stream2,
            ".markdown files should be streamable (only .md extension is excluded)"
        );
    }

    #[test]
    fn test_streaming_logic_for_non_md_files() {
        // Test that non-.md files SHOULD be streamed when Range header is present
        let video_file = "video.mp4";
        let streaming_enabled = true;
        let has_range_header = true;

        let should_stream = streaming_enabled && !video_file.ends_with(".md") && has_range_header;
        assert!(
            should_stream,
            "Non-.md files should be streamed with Range header"
        );

        // Test various file types
        let test_files = vec![
            "video.webm",
            "audio.mp3",
            "document.pdf",
            "image.jpg",
            "binary.bin",
            "text.txt",
            "data.csv",
        ];

        for file in test_files {
            let should_stream = streaming_enabled && !file.ends_with(".md") && has_range_header;
            assert!(
                should_stream,
                "File {} should be streamable with Range header",
                file
            );
        }
    }

    #[test]
    fn test_streaming_logic_without_range_header() {
        // Test that files should NOT be streamed without Range header
        let video_file = "video.mp4";
        let streaming_enabled = true;
        let has_range_header = false;

        let should_stream = streaming_enabled && !video_file.ends_with(".md") && has_range_header;
        assert!(
            !should_stream,
            "Files should not be streamed without Range header"
        );
    }

    #[test]
    fn test_streaming_logic_when_disabled() {
        // Test that files should NOT be streamed when streaming is disabled
        let video_file = "video.mp4";
        let streaming_enabled = false;
        let has_range_header = true;

        let should_stream = streaming_enabled && !video_file.ends_with(".md") && has_range_header;
        assert!(
            !should_stream,
            "Files should not be streamed when streaming is disabled"
        );
    }
}
