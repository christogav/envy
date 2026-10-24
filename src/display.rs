//! Showing untrusted text on the terminal: quoted, with every character
//! that could act on the terminal or hide itself escaped.

/// `value` in double quotes with everything that could move the cursor,
/// recolour or retitle the terminal, or reorder the text written out as an
/// escape: `\"`, `\\`, `\n`, `\r`, `\t`, and `\u{..}` for the other control
/// characters (including ESC and DEL) and for invisible formatting characters
/// (see [`is_invisible_or_control`]).
/// Other text, accents and CJK included, is shown as is.
/// Characters that must not reach the terminal as they are: controls, and
/// characters that draw nothing or reorder text, which could hide a payload
/// (tag characters) or spoof what a value looks like. A general rule over
/// Unicode blocks, not a list of known offenders. Variation selectors,
/// U+FE0F (emoji presentation) included, are escaped on purpose: an emoji
/// value is rare and a hidden character is worse than a less pretty one.
pub(crate) fn is_invisible_or_control(c: char) -> bool {
    c.is_control()
        || matches!(c as u32,
            0x00ad
            | 0x034f
            | 0x061c
            | 0x115f..=0x1160
            | 0x17b4..=0x17b5
            | 0x180b..=0x180f
            | 0x200b..=0x200f
            | 0x2028..=0x202e
            | 0x2060..=0x206f
            | 0x3164
            | 0xfe00..=0xfe0f
            | 0xfeff
            | 0xffa0
            | 0xfff0..=0xfffb
            | 0x1bca0..=0x1bca3
            | 0x1d173..=0x1d17a
            | 0xe0000..=0xe0fff)
}

pub(crate) fn quote_for_display(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if is_invisible_or_control(c) => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
