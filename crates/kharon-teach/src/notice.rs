//! The page the browser opens first: what the recorder does with what a person types, and one
//! link that starts the recording.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

pub const NOTICE: &str = "kharon-teach records how a login works so kharon can learn it.\n\
Use a THROWAWAY account. Everything you type in the window that\n\
opens is read by this program. Nothing you type is saved, and\n\
nothing is sent anywhere. The result is one file on this computer.\n";

const KEEP: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The notice page as HTML text. It holds no script.
pub fn notice_page_html(login_url: &url::Url) -> String {
    let host = login_url.host_str().unwrap_or("the login page");
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>kharon-teach</title></head>\
<body><pre>{notice}</pre><p><a href=\"{href}\">Start recording and open {host}</a></p></body></html>",
        notice = escape_html(NOTICE),
        href = escape_html(login_url.as_str()),
        host = escape_html(host),
    )
}

/// A `data:` URL page that shows [`NOTICE`] and one link, "Start recording and open <host>", to
/// `login_url`.
pub fn notice_page_url(login_url: &url::Url) -> String {
    let html = notice_page_html(login_url);
    format!(
        "data:text/html;charset=utf-8,{}",
        utf8_percent_encode(&html, KEEP)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_shows_the_notice_and_one_link_to_the_login_url() {
        let url = url::Url::parse("https://login.example.test/sign-in?next=a").unwrap();
        let html = notice_page_html(&url);
        assert!(html.contains("THROWAWAY"));
        assert!(html.contains("Start recording and open login.example.test"));
        assert_eq!(html.matches("<a ").count(), 1);
        assert!(html.contains(r#"href="https://login.example.test/sign-in?next=a""#));
        assert!(!html.contains("<script"));
    }

    #[test]
    fn hostile_characters_are_escaped_and_the_href_round_trips() {
        let url = url::Url::parse("https://a.test/p?x=1&y='2'&z=<b>\"q\"&w=%3Cscript%3E").unwrap();
        let html = notice_page_html(&url);
        let start = html.find("href=\"").unwrap() + 6;
        let end = start + html[start..].find('"').unwrap();
        let attr = &html[start..end];
        assert!(!attr.contains('<') && !attr.contains('\'') && !attr.contains('>'));
        let back = attr
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&#39;", "'")
            .replace("&quot;", "\"")
            .replace("&amp;", "&");
        assert_eq!(back, url.as_str());
        assert_eq!(html.matches("<a ").count(), 1);
        assert!(!html.contains("<b>"));
    }

    #[test]
    fn the_url_is_a_data_url_with_no_raw_markup() {
        let url = url::Url::parse("https://a.test/").unwrap();
        let page = notice_page_url(&url);
        let body = page.strip_prefix("data:text/html;charset=utf-8,").unwrap();
        assert!(!body.contains('<') && !body.contains(' ') && !body.contains('"'));
        let decoded = percent_encoding::percent_decode_str(body)
            .decode_utf8()
            .unwrap();
        assert_eq!(decoded, notice_page_html(&url));
    }
}
