//! Confusable skeletons for tool names (UTS #39 style, curated subset).
//!
//! The skeleton of a name is computed by NFKD normalization (which folds
//! full-width and mathematical alphanumerics to ASCII), removal of combining
//! marks, mapping of common Cyrillic/Greek/Latin look-alikes and digits to
//! their Latin prototypes, lower-casing, collapsing `rn` → `m` and `vv` → `w`,
//! and unifying separators. Two names with equal skeletons look the same to
//! a human. The mapping table is a curated subset of Unicode
//! `confusables.txt` covering the scripts seen in practice; it is not the
//! full table.

use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;

/// Look-alike → Latin prototype.
const MAP: &[(char, char)] = &[
    // Cyrillic lower case
    ('а', 'a'),
    ('в', 'b'),
    ('е', 'e'),
    ('ё', 'e'),
    ('һ', 'h'),
    ('і', 'i'),
    ('ї', 'i'),
    ('ј', 'j'),
    ('к', 'k'),
    ('ӏ', 'l'),
    ('м', 'm'),
    ('н', 'h'),
    ('о', 'o'),
    ('р', 'p'),
    ('ԛ', 'q'),
    ('с', 'c'),
    ('ѕ', 's'),
    ('т', 't'),
    ('у', 'y'),
    ('ԝ', 'w'),
    ('х', 'x'),
    ('ԁ', 'd'),
    ('ь', 'b'),
    ('г', 'r'),
    ('п', 'n'),
    ('ɡ', 'g'),
    // Cyrillic upper case
    ('А', 'a'),
    ('В', 'b'),
    ('Е', 'e'),
    ('Н', 'h'),
    ('І', 'i'),
    ('Ј', 'j'),
    ('К', 'k'),
    ('М', 'm'),
    ('О', 'o'),
    ('Р', 'p'),
    ('С', 'c'),
    ('Ѕ', 's'),
    ('Т', 't'),
    ('У', 'y'),
    ('Х', 'x'),
    ('Ԁ', 'd'),
    ('Ү', 'y'),
    ('Ԝ', 'w'),
    ('Ӏ', 'l'),
    // Greek
    ('α', 'a'),
    ('β', 'b'),
    ('ε', 'e'),
    ('η', 'n'),
    ('ι', 'i'),
    ('κ', 'k'),
    ('ν', 'v'),
    ('ο', 'o'),
    ('ρ', 'p'),
    ('τ', 't'),
    ('υ', 'u'),
    ('χ', 'x'),
    ('γ', 'y'),
    ('ω', 'w'),
    ('Α', 'a'),
    ('Β', 'b'),
    ('Ε', 'e'),
    ('Ζ', 'z'),
    ('Η', 'h'),
    ('Ι', 'i'),
    ('Κ', 'k'),
    ('Μ', 'm'),
    ('Ν', 'n'),
    ('Ο', 'o'),
    ('Ρ', 'p'),
    ('Τ', 't'),
    ('Υ', 'y'),
    ('Χ', 'x'),
    // Latin look-alikes and digits
    ('ı', 'i'),
    ('ȷ', 'j'),
    ('ł', 'l'),
    ('ƚ', 'l'),
    ('ɩ', 'i'),
    ('ʟ', 'l'),
    ('ꞵ', 'b'),
    ('0', 'o'),
    ('1', 'l'),
    ('|', 'l'),
    ('5', 's'),
    ('Ⅰ', 'l'),
    // Separators
    ('-', '_'),
    ('.', '_'),
    (' ', '_'),
    ('‐', '_'),
    ('‑', '_'),
    ('–', '_'),
    ('—', '_'),
    ('·', '_'),
];

fn map_char(c: char) -> char {
    MAP.iter().find(|(from, _)| *from == c).map_or(c, |(_, to)| *to)
}

/// Computes the confusable skeleton of `s`.
pub fn skeleton(s: &str) -> String {
    let mapped: String = s
        .nfkd()
        .filter(|c| !is_combining_mark(*c))
        .filter(|c| !matches!(*c as u32, 0x200B..=0x200F | 0x2060..=0x2064 | 0xFEFF | 0xE0000..=0xE007F))
        .map(map_char)
        .flat_map(char::to_lowercase)
        .map(|c| match c {
            'i' | 'l' => 'l',
            other => other,
        })
        .collect();
    mapped.replace("rn", "m").replace("vv", "w")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confusable_names_collapse() {
        assert_eq!(skeleton("send_email"), skeleton("sеnd_emаil"), "Cyrillic е and а");
        assert_eq!(skeleton("read_file"), skeleton("ｒｅａｄ＿ｆｉｌｅ"), "full-width");
        assert_eq!(skeleton("get_issues"), skeleton("get-lssues"));
        assert_eq!(skeleton("modern"), skeleton("modem"));
        assert_eq!(skeleton("café"), skeleton("cafe"));
        assert_eq!(skeleton("rea\u{200B}d"), skeleton("read"));
        assert_ne!(skeleton("read_file"), skeleton("write_file"));
    }
}
