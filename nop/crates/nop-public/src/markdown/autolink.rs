// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use pulldown_cmark::{CowStr, Event, LinkType, Tag, TagEnd};

pub(super) fn autolink_text_events(text: CowStr<'_>) -> Vec<Event<'_>> {
    let ranges = find_http_urls(&text);
    if ranges.is_empty() {
        return vec![Event::Text(text)];
    }

    let mut events = Vec::new();
    let mut cursor = 0usize;
    for (start, end) in ranges {
        if start > cursor {
            events.push(Event::Text(owned_cowstr(&text[cursor..start])));
        }
        let url = &text[start..end];
        events.push(Event::Start(Tag::Link {
            link_type: LinkType::Autolink,
            dest_url: owned_cowstr(url),
            title: CowStr::Borrowed(""),
            id: CowStr::Borrowed(""),
        }));
        events.push(Event::Text(owned_cowstr(url)));
        events.push(Event::End(TagEnd::Link));
        cursor = end;
    }
    if cursor < text.len() {
        events.push(Event::Text(owned_cowstr(&text[cursor..])));
    }
    events
}

fn owned_cowstr(value: &str) -> CowStr<'static> {
    CowStr::Boxed(value.to_string().into_boxed_str())
}

pub(super) fn find_http_urls(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut ranges = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let Some(scheme_len) = scheme_len_at(bytes, index) else {
            index += 1;
            continue;
        };
        if !can_start_url(text, index) {
            index += 1;
            continue;
        }
        let Some(end) = scan_url_end(bytes, index, scheme_len) else {
            index += 1;
            continue;
        };
        ranges.push((index, end));
        index = end;
    }
    ranges
}

fn scheme_len_at(bytes: &[u8], index: usize) -> Option<usize> {
    let rest = &bytes[index..];
    if rest.len() >= 8 && rest[..8].eq_ignore_ascii_case(b"https://") {
        return Some(8);
    }
    if rest.len() >= 7 && rest[..7].eq_ignore_ascii_case(b"http://") {
        return Some(7);
    }
    None
}

fn can_start_url(text: &str, index: usize) -> bool {
    if index == 0 {
        return true;
    }
    let Some(previous) = text[..index].chars().next_back() else {
        return true;
    };
    !previous.is_ascii_alphanumeric() && previous != '_' && previous != '/'
}

fn scan_url_end(bytes: &[u8], start: usize, scheme_len: usize) -> Option<usize> {
    let mut end = start + scheme_len;
    if end >= bytes.len() || !is_url_body_byte(bytes[end]) {
        return None;
    }
    end += 1;
    while end < bytes.len() && is_url_body_byte(bytes[end]) {
        end += 1;
    }
    while end > start + scheme_len {
        let last = bytes[end - 1];
        if matches!(last, b'.' | b',' | b';' | b':' | b'!' | b'?') {
            end -= 1;
            continue;
        }
        if matches!(last, b')' | b']' | b'}' | b'>') && unbalanced_closer(bytes, start, end, last) {
            end -= 1;
            continue;
        }
        break;
    }
    if end <= start + scheme_len {
        return None;
    }
    Some(end)
}

fn is_url_body_byte(byte: u8) -> bool {
    !byte.is_ascii_whitespace()
        && byte != b'<'
        && byte != b'"'
        && byte != b'\''
        && byte != 0x00
        && !byte.is_ascii_control()
}

fn unbalanced_closer(bytes: &[u8], start: usize, end: usize, closer: u8) -> bool {
    let opener = match closer {
        b')' => b'(',
        b']' => b'[',
        b'}' => b'{',
        b'>' => b'<',
        _ => return false,
    };
    let mut open = 0i32;
    let mut close = 0i32;
    for &byte in &bytes[start..end] {
        if byte == opener {
            open += 1;
        } else if byte == closer {
            close += 1;
        }
    }
    close > open
}

#[cfg(test)]
mod tests {
    use super::{autolink_text_events, find_http_urls};
    use pulldown_cmark::{Event, Tag, TagEnd};

    #[test]
    fn finds_http_and_https_urls() {
        assert_eq!(
            find_http_urls("see https://example.com/docs and http://example.org"),
            vec![(4, 28), (33, 51)]
        );
    }

    #[test]
    fn ignores_scheme_less_and_non_http_urls() {
        assert!(
            find_http_urls("www.example.com mailto:user@example.com javascript:alert(1)")
                .is_empty()
        );
    }

    #[test]
    fn strips_trailing_punctuation() {
        assert_eq!(find_http_urls("Visit https://example.com."), vec![(6, 25)]);
        assert_eq!(find_http_urls("(https://example.com/path)"), vec![(1, 25)]);
        assert_eq!(
            find_http_urls("https://en.wikipedia.org/wiki/Rust_(programming_language)"),
            vec![(0, 57)]
        );
    }

    #[test]
    fn skips_urls_glued_to_identifiers() {
        assert!(find_http_urls("seehttp://example.com").is_empty());
    }

    #[test]
    fn emits_autolink_events_around_url() {
        let events = autolink_text_events("See https://example.com now.".into());
        assert!(matches!(
            events[1],
            Event::Start(Tag::Link {
                dest_url: ref url,
                ..
            }) if url.as_ref() == "https://example.com"
        ));
        assert!(
            matches!(events[2], Event::Text(ref text) if text.as_ref() == "https://example.com")
        );
        assert!(matches!(events[3], Event::End(TagEnd::Link)));
        assert!(matches!(events[0], Event::Text(ref text) if text.as_ref() == "See "));
        assert!(matches!(events[4], Event::Text(ref text) if text.as_ref() == " now."));
    }
}
