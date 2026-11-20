// Copyright 2022 TiKV Project Authors. Licensed under Apache-2.0.

use std::{borrow::Cow, collections::HashSet};

use regex::Regex;
use tidb_query_codegen::rpn_fn;
use tidb_query_common::Result;
use tidb_query_datatype::codec::{Error, collation::Collator, data_type::*};
use tipb::{Expr, ExprType};

const PATTERN_IDX: usize = 1;
const LIKE_MATCH_IDX: usize = 2;
const SUBSTR_MATCH_IDX: usize = 4;
const INSTR_MATCH_IDX: usize = 5;
const REPLACE_MATCH_IDX: usize = 5;

fn invalid_pos_error(pos: i64, count: usize) -> Error {
    Error::regexp_error(format!("Invalid pos: {} in regexp, count: {}", pos, count))
}

/// A regexp haystack decoded the way TiDB does it.
///
/// TiDB hands the raw bytes to Go's `regexp` package, which decodes the input
/// with `utf8.DecodeRune`: every byte of a malformed UTF-8 sequence is treated
/// as one U+FFFD rune. Input in a non-UTF-8 charset (e.g. latin1, where 0xFF
/// is a valid character) therefore must not fail the query; its bytes match as
/// U+FFFD instead.
///
/// `decoded` holds the resulting UTF-8 text the regex runs over, and
/// `boundaries` aligns its character boundaries with the raw bytes so that
/// matches can be reported as the original bytes, like TiDB does.
struct RegexpHaystack<'a> {
    decoded: String,
    raw: &'a [u8],
    /// `(decoded offset, raw offset)` of every character in `decoded`, plus a
    /// trailing entry for the end of the string. Empty when the input was
    /// valid UTF-8, in which case both offsets coincide.
    boundaries: Vec<(usize, usize)>,
}

impl<'a> RegexpHaystack<'a> {
    fn decode(data: &'a [u8]) -> RegexpHaystack<'a> {
        if let Ok(text) = std::str::from_utf8(data) {
            return RegexpHaystack {
                decoded: text.to_owned(),
                raw: data,
                boundaries: Vec::new(),
            };
        }

        let mut decoded = String::with_capacity(data.len());
        let mut boundaries = Vec::with_capacity(data.len() + 1);
        let mut raw_offset = 0;
        while raw_offset < data.len() {
            // Mirror Go's utf8.DecodeRune: a byte that does not begin a valid
            // UTF-8 sequence yields U+FFFD and consumes one byte.
            let width = match data[raw_offset] {
                0xC2..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF4 => 4,
                _ => 1,
            };
            match data
                .get(raw_offset..raw_offset + width)
                .and_then(|seq| std::str::from_utf8(seq).ok())
                .filter(|seq| seq.chars().count() == 1)
            {
                Some(seq) => {
                    boundaries.push((decoded.len(), raw_offset));
                    decoded.push_str(seq);
                    raw_offset += width;
                }
                None => {
                    boundaries.push((decoded.len(), raw_offset));
                    decoded.push(char::REPLACEMENT_CHARACTER);
                    raw_offset += 1;
                }
            }
        }
        boundaries.push((decoded.len(), raw_offset));

        RegexpHaystack {
            decoded,
            raw: data,
            boundaries,
        }
    }

    /// Maps a character boundary of `decoded` to the offset in the raw bytes.
    fn raw_offset(&self, decoded_offset: usize) -> usize {
        // Valid UTF-8 input keeps a one-to-one offset correspondence.
        if self.boundaries.is_empty() {
            return decoded_offset;
        }
        match self
            .boundaries
            .binary_search_by_key(&decoded_offset, |(d, _)| *d)
        {
            Ok(idx) => self.boundaries[idx].1,
            // Unreachable for offsets taken from matches on `decoded`.
            Err(idx) => self.boundaries[idx.saturating_sub(1)].1,
        }
    }

    /// Returns the raw bytes behind `decoded[from..to]`, which must both be
    /// character boundaries of `decoded`.
    fn raw_bytes(&self, from: usize, to: usize) -> &'a [u8] {
        &self.raw[self.raw_offset(from)..self.raw_offset(to)]
    }
}

fn is_valid_match_type(m: char) -> bool {
    matches!(m, 'i' | 'c' | 'm' | 's')
}

fn get_match_type<C: Collator>(match_type: &[u8]) -> Result<String> {
    let match_type = std::str::from_utf8(match_type)?;
    let mut flag_set = HashSet::<char>::new();

    if C::IS_CASE_INSENSITIVE {
        flag_set.insert('i');
    }

    for m in match_type.chars() {
        if !is_valid_match_type(m) {
            let err = format!("Invalid match type: {} in regexp", m);
            return Err(Error::regexp_error(err).into());
        }
        if m == 'c' {
            // re2 is case-sensitive by default, so we only need to delete 'i' flag
            // to enable the case-sensitive for the regexp.
            flag_set.remove(&'i');
            continue;
        }
        flag_set.insert(m);
    }

    let mut flag = String::new();
    for m in flag_set {
        flag.push(m);
    }

    Ok(flag)
}

fn build_regexp<C: Collator>(pattern: &[u8], match_type: &[u8]) -> Result<Regex> {
    if pattern.is_empty() {
        return Err(Error::regexp_error("Empty pattern is invalid in regexp".into()).into());
    }

    let match_type = get_match_type::<C>(match_type)?;

    let pattern = String::from_utf8(pattern.to_vec())?;
    let pattern_with_tp = if !match_type.is_empty() {
        format!("(?{}){}", match_type, pattern)
    } else {
        pattern
    };

    Regex::new(&pattern_with_tp)
        .map_err(|e| Error::regexp_error(format!("Invalid regexp pattern: {:?}", e)).into())
}

fn build_regexp_from_args<C: Collator>(
    args: &[ScalarValueRef<'_>],
    match_idx: usize,
) -> Result<Option<Regex>> {
    let pattern = match args[PATTERN_IDX].as_bytes() {
        Some(b) => b,
        None => return Ok(None),
    };

    let match_type = if args.len() > match_idx {
        match args[match_idx].as_bytes() {
            Some(b) => b,
            None => return Ok(None),
        }
    } else {
        b""
    };

    build_regexp::<C>(pattern, match_type).map(Some)
}

fn init_regexp_data<C: Collator, const N: usize>(expr: &mut Expr) -> Result<Option<Regex>> {
    let children = expr.mut_children();
    if children.len() <= PATTERN_IDX {
        return Ok(None);
    }

    let pattern = match children[PATTERN_IDX].get_tp() {
        ExprType::Bytes | ExprType::String => children[PATTERN_IDX].get_val(),
        _ => return Ok(None),
    };

    let match_type = if children.len() > N {
        match children[N].get_tp() {
            ExprType::Bytes | ExprType::String => children[N].get_val(),
            _ => return Ok(None),
        }
    } else {
        b""
    };

    build_regexp::<C>(pattern, match_type).map(Some)
}

/// TiDB evaluates regular expressions with Go's `regexp` package, which never
/// fails on malformed UTF-8: each invalid byte is one U+FFFD rune.
/// See https://dev.mysql.com/doc/refman/8.0/en/regexp.html#function_regexp-like.
#[rpn_fn(nullable, raw_varg, min_args = 2, max_args = 3, capture = [metadata], metadata_mapper = init_regexp_data::<C, LIKE_MATCH_IDX>)]
#[inline]
pub fn regexp_like<C: Collator>(
    metadata: &Option<Regex>,
    args: &[ScalarValueRef<'_>],
) -> Result<Option<i64>> {
    let expr = match args[0].as_bytes() {
        Some(e) => RegexpHaystack::decode(e),
        None => return Ok(None),
    };
    let regex = match metadata {
        Some(r) => Cow::Borrowed(r),
        None => match build_regexp_from_args::<C>(args, LIKE_MATCH_IDX)? {
            Some(r) => Cow::Owned(r),
            None => return Ok(None),
        },
    };

    Ok(Some(regex.is_match(&expr.decoded) as i64))
}

/// TiDB evaluates regular expressions with Go's `regexp` package, which never
/// fails on malformed UTF-8: each invalid byte is one U+FFFD rune.
/// See https://dev.mysql.com/doc/refman/8.0/en/regexp.html#function_regexp-substr.
#[rpn_fn(nullable, raw_varg, min_args = 2, max_args = 5, capture = [metadata], metadata_mapper = init_regexp_data::<C, SUBSTR_MATCH_IDX>)]
#[inline]
pub fn regexp_substr<C: Collator>(
    metadata: &Option<Regex>,
    args: &[ScalarValueRef<'_>],
) -> Result<Option<Bytes>> {
    let haystack = match args[0].as_bytes() {
        Some(e) => RegexpHaystack::decode(e),
        None => return Ok(None),
    };
    let regex = match metadata {
        Some(r) => Cow::Borrowed(r),
        None => match build_regexp_from_args::<C>(args, SUBSTR_MATCH_IDX)? {
            Some(r) => Cow::Owned(r),
            None => return Ok(None),
        },
    };

    // TiDB trims the string before the given character position, so positions
    // count the characters of the decoded text.
    let mut expr: &str = &haystack.decoded;
    let mut trim = 0;
    if args.len() >= 3 {
        let pos = match EvaluableRef::borrow_scalar_value_ref(args[2]) {
            Some::<&i64>(p) => *p,
            None => return Ok(None),
        };

        if pos >= 1 {
            if let Some((idx, _)) = expr.char_indices().nth((pos - 1) as usize) {
                trim = idx;
                expr = &expr[idx..];
            } else if pos != 1 {
                // Char count == 0 && pos == 1 is valid.
                return Err(invalid_pos_error(pos, expr.chars().count()).into());
            }
        } else {
            return Err(invalid_pos_error(pos, expr.chars().count()).into());
        }
    }

    let mut occurrence = 1i64;
    if args.len() >= 4 {
        occurrence = match EvaluableRef::borrow_scalar_value_ref(args[3]) {
            Some::<&i64>(o) => *o,
            None => return Ok(None),
        };

        if occurrence < 1 {
            occurrence = 1;
        }
    };

    if let Some(m) = regex.find_iter(expr).nth((occurrence - 1) as usize) {
        // Report the original bytes behind the match, like TiDB does.
        return Ok(Some(
            haystack
                .raw_bytes(trim + m.start(), trim + m.end())
                .to_vec(),
        ));
    }

    Ok(None)
}

/// TiDB evaluates regular expressions with Go's `regexp` package, which never
/// fails on malformed UTF-8: each invalid byte is one U+FFFD rune.
/// See https://dev.mysql.com/doc/refman/8.0/en/regexp.html#function_regexp-instr.
#[rpn_fn(nullable, raw_varg, min_args = 2, max_args = 6, capture = [metadata], metadata_mapper = init_regexp_data::<C, INSTR_MATCH_IDX>)]
#[inline]
pub fn regexp_instr<C: Collator>(
    metadata: &Option<Regex>,
    args: &[ScalarValueRef<'_>],
) -> Result<Option<i64>> {
    let haystack = match args[0].as_bytes() {
        Some(e) => RegexpHaystack::decode(e),
        None => return Ok(None),
    };
    let mut expr: &str = &haystack.decoded;
    let regex = match metadata {
        Some(r) => Cow::Borrowed(r),
        None => match build_regexp_from_args::<C>(args, INSTR_MATCH_IDX)? {
            Some(r) => Cow::Owned(r),
            None => return Ok(None),
        },
    };

    let mut pos = 1i64;
    if args.len() >= 3 {
        pos = match EvaluableRef::borrow_scalar_value_ref(args[2]) {
            Some::<&i64>(p) => *p,
            None => return Ok(None),
        };

        if pos >= 1 {
            if let Some((idx, _)) = expr.char_indices().nth((pos - 1) as usize) {
                expr = &expr[idx..];
            } else if pos != 1 {
                // Char count == 0 && pos == 1 is valid.
                return Err(invalid_pos_error(pos, expr.chars().count()).into());
            }
        } else {
            return Err(invalid_pos_error(pos, expr.chars().count()).into());
        }
    }

    let mut occurrence = 1i64;
    if args.len() >= 4 {
        occurrence = match EvaluableRef::borrow_scalar_value_ref(args[3]) {
            Some::<&i64>(o) => *o,
            None => return Ok(None),
        };

        if occurrence < 1 {
            occurrence = 1;
        }
    };

    let mut return_option = 0i64;
    if args.len() >= 5 {
        return_option = match EvaluableRef::borrow_scalar_value_ref(args[4]) {
            Some::<&i64>(o) => *o,
            None => return Ok(None),
        };

        if return_option != 0 && return_option != 1 {
            let err = format!("Invalid regexp return option: {}", return_option);
            return Err(Error::regexp_error(err).into());
        }
    };

    if let Some(m) = regex.find_iter(expr).nth((occurrence - 1) as usize) {
        let find_pos = if return_option == 0 {
            m.start()
        } else {
            m.end()
        };

        let count = expr[..find_pos].chars().count() as i64;
        return Ok(Some(count + pos));
    }

    Ok(Some(0))
}

#[derive(Clone)]
enum ReplaceInstruction {
    SubstitutionNum(usize),
    Literal(Vec<u8>),
}

pub struct ReplaceMetaData {
    regex: Option<Regex>,
    instructions: Option<Vec<ReplaceInstruction>>,
}

fn init_regexp_replace_data<C: Collator>(expr: &mut Expr) -> Result<ReplaceMetaData> {
    let mut meta = ReplaceMetaData {
        regex: init_regexp_data::<C, REPLACE_MATCH_IDX>(expr)?,
        instructions: None,
    };

    let children = expr.mut_children();
    if children.len() >= 3 {
        match children[2].get_tp() {
            ExprType::Bytes | ExprType::String => {
                meta.instructions = Some(init_replace_instructions(children[2].get_val()));
            }
            _ => {}
        };
    }

    Ok(meta)
}

fn init_replace_instructions(replace_expr: &[u8]) -> Vec<ReplaceInstruction> {
    let mut instructions = Vec::new();
    let len = replace_expr.len();
    let mut literal = Vec::new();
    let mut i = 0;
    while i < len {
        if replace_expr[i] == b'\\' {
            if i + 1 >= len {
                // This slash is in the end. Ignore it and break the loop.
                break;
            }
            if replace_expr[i + 1].is_ascii_digit() {
                if !literal.is_empty() {
                    instructions.push(ReplaceInstruction::Literal(literal));
                    literal = Vec::new();
                }
                instructions.push(ReplaceInstruction::SubstitutionNum(
                    (replace_expr[i + 1] - b'0').into(),
                ));
            } else {
                literal.push(replace_expr[i + 1]);
            }
            i += 2;
        } else {
            literal.push(replace_expr[i]);
            i += 1;
        }
    }
    if !literal.is_empty() {
        instructions.push(ReplaceInstruction::Literal(literal));
    }

    instructions
}

/// TiDB evaluates regular expressions with Go's `regexp` package, which never
/// fails on malformed UTF-8: each invalid byte is one U+FFFD rune.
/// See https://dev.mysql.com/doc/refman/8.0/en/regexp.html#function_regexp-replace.
#[rpn_fn(nullable, raw_varg, min_args = 3, max_args = 6, capture = [metadata], metadata_mapper = init_regexp_replace_data::<C>)]
#[inline]
pub fn regexp_replace<C: Collator>(
    metadata: &ReplaceMetaData,
    args: &[ScalarValueRef<'_>],
) -> Result<Option<Bytes>> {
    let haystack = match args[0].as_bytes() {
        Some(e) => RegexpHaystack::decode(e),
        None => return Ok(None),
    };
    let expr: &str = &haystack.decoded;
    let regex = match metadata.regex.as_ref() {
        Some(r) => Cow::Borrowed(r),
        None => match build_regexp_from_args::<C>(args, REPLACE_MATCH_IDX)? {
            Some(r) => Cow::Owned(r),
            None => return Ok(None),
        },
    };
    let replace_inst = match metadata.instructions.as_ref() {
        Some(i) => Cow::Borrowed(i),
        None => match args[2].as_bytes() {
            Some(e) => Cow::Owned(init_replace_instructions(e)),
            None => return Ok(None),
        },
    };

    let (mut trim, mut trimmed) = (0, expr);
    if args.len() >= 4 {
        let pos = match EvaluableRef::borrow_scalar_value_ref(args[3]) {
            Some::<&i64>(p) => *p,
            None => return Ok(None),
        };

        if pos >= 1 {
            if let Some((idx, _)) = expr.char_indices().nth((pos - 1) as usize) {
                trim = idx;
                trimmed = &expr[idx..];
            } else if pos != 1 {
                // Char count == 0 && pos == 1 is valid.
                return Err(invalid_pos_error(pos, expr.chars().count()).into());
            }
        } else {
            return Err(invalid_pos_error(pos, expr.chars().count()).into());
        }
    }

    let mut occurrence = 0i64;
    if args.len() >= 5 {
        occurrence = match EvaluableRef::borrow_scalar_value_ref(args[4]) {
            Some::<&i64>(o) => *o,
            None => return Ok(None),
        };

        if occurrence < 0 {
            occurrence = 1;
        }
    };

    let replace_work = |capture: &regex::Captures, res: &mut Vec<u8>| -> Result<()> {
        for inst in replace_inst.as_ref() {
            match inst {
                ReplaceInstruction::SubstitutionNum(num) => {
                    let m = capture.get(*num).ok_or_else(|| {
                        Error::regexp_error(format!(
                            "Substitution number is out of range: {}",
                            *num
                        ))
                    })?;
                    // Copy the original bytes behind the capture, like TiDB.
                    res.extend(haystack.raw_bytes(trim + m.start(), trim + m.end()));
                }
                ReplaceInstruction::Literal(lit) => {
                    res.extend(lit);
                }
            }
        }
        Ok(())
    };

    let mut result = Vec::new();
    result.extend(haystack.raw_bytes(0, trim));
    let mut last_match = 0;
    if occurrence == 0 {
        for capture in regex.captures_iter(trimmed) {
            // unwrap on 0 is OK because captures only reports matches.
            let m = capture.get(0).unwrap();
            result.extend(haystack.raw_bytes(trim + last_match, trim + m.start()));
            last_match = m.end();
            replace_work(&capture, &mut result)?;
        }
    } else if let Some(capture) = regex.captures_iter(trimmed).nth((occurrence - 1) as usize) {
        // unwrap on 0 is OK because captures only reports matches.
        let m = capture.get(0).unwrap();
        result.extend(haystack.raw_bytes(trim, trim + m.start()));
        last_match = m.end();
        replace_work(&capture, &mut result)?;
    }
    result.extend(haystack.raw_bytes(trim + last_match, expr.len()));

    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use tidb_query_datatype::{
        Collation, EvalType, FieldTypeAccessor, FieldTypeTp,
        codec::batch::{LazyBatchColumn, LazyBatchColumnVec},
        expr::EvalContext,
    };
    use tipb::ScalarFuncSig;
    use tipb_helper::ExprDefBuilder;

    use super::RegexpHaystack;
    use crate::RpnExpressionBuilder;

    #[test]
    fn test_regexp_haystack_decode() {
        // Valid UTF-8 keeps a one-to-one offset correspondence.
        let h = RegexpHaystack::decode("a你b".as_bytes());
        assert_eq!(h.decoded, "a你b");
        assert!(h.boundaries.is_empty());
        assert_eq!(h.raw_bytes(0, h.decoded.len()), "a你b".as_bytes());
        assert_eq!(h.raw_bytes(1, "a你".len()), "你".as_bytes());

        // Every malformed byte decodes to one U+FFFD, like Go's utf8.DecodeRune
        // that TiDB's regexp relies on.
        let cases: Vec<(&[u8], &str)> = vec![
            (&[0xFF], "\u{FFFD}"),               // latin1 ÿ
            (&[0xE9], "\u{FFFD}"),               // latin1 é
            (&[0xC3, 0x28], "\u{FFFD}("),        // broken two-byte sequence
            (&[0xE4, 0xB8], "\u{FFFD}\u{FFFD}"), // truncated three-byte sequence
            (&[0xF0, 0x9F], "\u{FFFD}\u{FFFD}"), // truncated four-byte sequence
            (
                &[0xF5, 0x80, 0x80, 0x80],
                "\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}",
            ), // out of range
            (&[0xED, 0xA0, 0x80], "\u{FFFD}\u{FFFD}\u{FFFD}"), // UTF-16 surrogate
            (&[0xC0, 0xAF], "\u{FFFD}\u{FFFD}"), // overlong encoding
            (&[0x61, 0xFF, 0x62], "a\u{FFFD}b"), // valid bytes around
            (&[0xE4, 0xB8, 0x80, 0xFF], "一\u{FFFD}"), // valid character then invalid
        ];
        for (data, decoded) in cases {
            let h = RegexpHaystack::decode(data);
            assert_eq!(h.decoded, decoded, "unexpected decoding for {:X?}", data);
            // The whole input maps back to itself.
            assert_eq!(h.raw_bytes(0, h.decoded.len()), data);
        }

        // Offsets of a mixed haystack map back to the original bytes. The
        // decoded text is "a\u{FFFD}一b", where \u{FFFD} occupies decoded
        // offsets 1..4 and "一" offsets 4..7.
        let h = RegexpHaystack::decode(&[b'a', 0xFF, 0xE4, 0xB8, 0x80, b'b']);
        assert_eq!(h.decoded, "a\u{FFFD}一b");
        assert_eq!(h.raw_bytes(1, 4), &[0xFF]);
        assert_eq!(h.raw_bytes(4, 7), &[0xE4, 0xB8, 0x80]);
        assert_eq!(h.raw_bytes(4, h.decoded.len()), &[0xE4, 0xB8, 0x80, b'b']);
    }

    #[test]
    fn test_regexp_like() {
        let cases = vec![
            ("a", "^$", None, Some(0)),
            ("a", "a", None, Some(1)),
            ("b", "a", None, Some(0)),
            ("aA", "Aa", None, Some(0)),
            ("aaa", ".", None, Some(1)),
            ("ab", "^.$", None, Some(0)),
            ("b", "..", None, Some(0)),
            ("aab", ".ab", None, Some(1)),
            ("abcd", ".*", None, Some(1)),
            ("你", "^.$", None, Some(1)),
            ("你好", "你好", None, Some(1)),
            ("你好", "^你好$", None, Some(1)),
            ("你好", "^您好$", None, Some(0)),
            // Test wrong pattern
            ("", "(", None, None),
            ("", "(*", None, None),
            ("", "[a", None, None),
            ("aa", "", None, None),
            ("你好", "", None, None),
            // Test case-insensitive
            ("abc", "AbC", Some(""), Some(0)),
            ("abc", "AbC", Some("i"), Some(1)),
            // Test multiple-line mode
            ("123\n321", "23$", Some(""), Some(0)),
            ("123\n321", "23$", Some("m"), Some(1)),
            ("good\nday", "^day", Some("m"), Some(1)),
            // Test s flag(in mysql it's n flag)
            ("\n", ".", Some(""), Some(0)),
            ("\n", ".", Some("s"), Some(1)),
            // Test rightmost rule
            ("abc", "aBc", Some("ic"), Some(0)),
            ("abc", "aBc", Some("ci"), Some(1)),
            // Test invalid match type
            ("abc", "abc", Some("p"), None),
            ("abc", "abc", Some("cpi"), None),
        ];

        for (expr, pattern, match_type, expected) in cases {
            let mut ctx = EvalContext::default();

            let mut builder =
                ExprDefBuilder::scalar_func(ScalarFuncSig::RegexpLikeSig, FieldTypeTp::LongLong);
            builder = builder
                .push_child(ExprDefBuilder::constant_bytes(expr.as_bytes().to_vec()))
                .push_child(ExprDefBuilder::constant_bytes(pattern.as_bytes().to_vec()));
            if let Some(m) = match_type {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(m.as_bytes().to_vec()));
            }

            let node = builder.build();
            let exp = RpnExpressionBuilder::build_from_expr_tree(node, &mut ctx, 1);
            if expected.is_none() {
                assert!(exp.is_err());
                continue;
            }
            let exp = exp.unwrap();

            let schema = &[];
            let mut columns = LazyBatchColumnVec::empty();

            let val = exp.eval(&mut ctx, schema, &mut columns, &[], 1).unwrap();

            assert!(val.is_vector());
            let v = val.vector_value().unwrap().as_ref().to_int_vec();
            assert_eq!(v.len(), 1);
            assert_eq!(v[0], expected);
        }

        // Test null
        let cases = vec![
            (None, Some("a"), Some("i")),
            (Some("a"), None, Some("i")),
            (Some("a"), Some("a"), None),
        ];
        for (expr, pattern, match_type) in cases {
            let mut ctx = EvalContext::default();

            let mut builder =
                ExprDefBuilder::scalar_func(ScalarFuncSig::RegexpSig, FieldTypeTp::LongLong);
            if let Some(e) = expr {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(e.as_bytes().to_vec()));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::String));
            }
            if let Some(p) = pattern {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(p.as_bytes().to_vec()));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::String));
            }
            if let Some(m) = match_type {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(m.as_bytes().to_vec()));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::String));
            }

            let node = builder.build();
            let exp = RpnExpressionBuilder::build_from_expr_tree(node, &mut ctx, 1).unwrap();

            let schema = &[];
            let mut columns = LazyBatchColumnVec::empty();

            let val = exp.eval(&mut ctx, schema, &mut columns, &[], 1).unwrap();
            assert!(val.is_vector());
            let v = val.vector_value().unwrap().as_ref().to_int_vec();
            assert_eq!(v.len(), 1);
            assert_eq!(v[0], None);
        }
    }

    #[test]
    fn test_regexp_substr() {
        let cases = vec![
            ("abc", "bc", None, None, None, Some("bc"), false),
            ("你好啊", "好", None, None, None, Some("好"), false),
            ("abc", "bc", Some(2), None, None, Some("bc"), false),
            ("你好啊", "好", Some(2), None, None, Some("好"), false),
            ("你好啊", "好", Some(3), None, None, None, false),
            // Test invalid position index
            ("你好啊", "好", Some(4), None, None, None, true),
            ("你好啊", "好", Some(-1), None, None, None, true),
            ("", "a", Some(1), None, None, None, false),
            (
                "abc abd abe",
                "ab.",
                Some(1),
                Some(1),
                None,
                Some("abc"),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(1),
                Some(0),
                None,
                Some("abc"),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(1),
                Some(-1),
                None,
                Some("abc"),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(1),
                Some(2),
                None,
                Some("abd"),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(3),
                Some(1),
                None,
                Some("abd"),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(3),
                Some(2),
                None,
                Some("abe"),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(6),
                Some(1),
                None,
                Some("abe"),
                false,
            ),
            ("abc abd abe", "ab.", Some(6), Some(100), None, None, false),
            ("abc abd abe", "ab.", Some(100), Some(1), None, None, true),
            (
                "嗯嗯 嗯好 嗯呐",
                "嗯.",
                Some(1),
                Some(1),
                None,
                Some("嗯嗯"),
                false,
            ),
            (
                "嗯嗯 嗯好 嗯呐",
                "嗯.",
                Some(1),
                Some(2),
                None,
                Some("嗯好"),
                false,
            ),
            (
                "嗯嗯 嗯好 嗯呐",
                "嗯.",
                Some(5),
                Some(1),
                None,
                Some("嗯呐"),
                false,
            ),
            ("嗯嗯 嗯好 嗯呐", "嗯.", Some(5), Some(2), None, None, false),
            ("abc", "ab.", Some(1), Some(1), Some(""), Some("abc"), false),
            (
                "abc",
                "aB.",
                Some(1),
                Some(1),
                Some("i"),
                Some("abc"),
                false,
            ),
            ("abc", "aB.", Some(100), Some(1), Some("i"), None, true),
            (
                "good\nday",
                "od",
                Some(1),
                Some(1),
                Some("m"),
                Some("od"),
                false,
            ),
            ("\n", ".", Some(1), Some(1), Some("s"), Some("\n"), false),
        ];

        for (expr, pattern, pos, occur, match_type, expected, error) in cases {
            let mut ctx = EvalContext::default();

            let mut builder =
                ExprDefBuilder::scalar_func(ScalarFuncSig::RegexpSubstrSig, FieldTypeTp::String);
            builder = builder
                .push_child(ExprDefBuilder::constant_bytes(expr.as_bytes().to_vec()))
                .push_child(ExprDefBuilder::constant_bytes(pattern.as_bytes().to_vec()));
            if let Some(p) = pos {
                builder = builder.push_child(ExprDefBuilder::constant_int(p));
            }
            if let Some(o) = occur {
                builder = builder.push_child(ExprDefBuilder::constant_int(o));
            }
            if let Some(m) = match_type {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(m.as_bytes().to_vec()));
            }

            let node = builder.build();
            let exp = RpnExpressionBuilder::build_from_expr_tree(node, &mut ctx, 1).unwrap();
            let schema = &[];
            let mut columns = LazyBatchColumnVec::empty();
            let val = exp.eval(&mut ctx, schema, &mut columns, &[], 1);
            match val {
                Ok(val) => {
                    assert!(val.is_vector());
                    let v = val.vector_value().unwrap().as_ref().to_bytes_vec();
                    assert_eq!(v.len(), 1);
                    assert_eq!(
                        v[0],
                        expected.map(|e| e.as_bytes().to_vec()),
                        "{:?} {:?} {:?}",
                        expr,
                        pattern,
                        pos
                    );
                }
                Err(e) => {
                    assert!(error, "val has error {:?}", e);
                }
            }
        }

        // Test null
        let cases = vec![
            (None, Some("a"), Some(1), Some(1), Some("i")),
            (Some("a"), None, Some(1), Some(1), Some("i")),
            (Some("a"), Some("a"), None, Some(1), Some("i")),
            (Some("a"), Some("a"), Some(1), None, Some("i")),
            (Some("a"), Some("a"), Some(1), Some(1), None),
        ];
        for (expr, pattern, pos, occur, match_type) in cases {
            let mut ctx = EvalContext::default();

            let mut builder =
                ExprDefBuilder::scalar_func(ScalarFuncSig::RegexpSubstrSig, FieldTypeTp::String);
            if let Some(e) = expr {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(e.as_bytes().to_vec()));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::String));
            }
            if let Some(p) = pattern {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(p.as_bytes().to_vec()));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::String));
            }
            if let Some(p) = pos {
                builder = builder.push_child(ExprDefBuilder::constant_int(p));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::LongLong));
            }
            if let Some(o) = occur {
                builder = builder.push_child(ExprDefBuilder::constant_int(o));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::LongLong));
            }
            if let Some(m) = match_type {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(m.as_bytes().to_vec()));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::String));
            }

            let node = builder.build();
            let exp = RpnExpressionBuilder::build_from_expr_tree(node, &mut ctx, 1).unwrap();

            let schema = &[];
            let mut columns = LazyBatchColumnVec::empty();

            let val = exp.eval(&mut ctx, schema, &mut columns, &[], 1).unwrap();
            assert!(val.is_vector());
            let v = val.vector_value().unwrap().as_ref().to_bytes_vec();
            assert_eq!(v.len(), 1);
            assert_eq!(v[0], None);
        }
    }

    #[test]
    fn test_regexp_instr() {
        let cases = vec![
            ("abc", "bc", None, None, None, None, Some(2), false),
            ("你好啊", "好", None, None, None, None, Some(2), false),
            ("abc", "bc", Some(2), None, None, None, Some(2), false),
            ("你好啊", "好", Some(2), None, None, None, Some(2), false),
            ("你好啊", "好", Some(3), None, None, None, Some(0), false),
            // Test invalid position index
            ("你好啊", "好", Some(4), None, None, None, Some(0), true),
            ("你好啊", "好", Some(-1), None, None, None, Some(0), true),
            ("", "a", Some(1), None, None, None, Some(0), false),
            (
                "abc abd abe",
                "ab.",
                Some(1),
                Some(1),
                None,
                None,
                Some(1),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(1),
                Some(0),
                None,
                None,
                Some(1),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(1),
                Some(-1),
                None,
                None,
                Some(1),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(1),
                Some(2),
                None,
                None,
                Some(5),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(3),
                Some(1),
                None,
                None,
                Some(5),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(3),
                Some(2),
                None,
                None,
                Some(9),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(6),
                Some(1),
                None,
                None,
                Some(9),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(6),
                Some(100),
                None,
                None,
                Some(0),
                false,
            ),
            (
                "嗯嗯 嗯好 嗯呐",
                "嗯.",
                Some(1),
                Some(1),
                None,
                None,
                Some(1),
                false,
            ),
            (
                "嗯嗯 嗯好 嗯呐",
                "嗯.",
                Some(1),
                Some(2),
                None,
                None,
                Some(4),
                false,
            ),
            (
                "嗯嗯 嗯好 嗯呐",
                "嗯.",
                Some(5),
                Some(1),
                None,
                None,
                Some(7),
                false,
            ),
            (
                "嗯嗯 嗯好 嗯呐",
                "嗯.",
                Some(5),
                Some(2),
                None,
                None,
                Some(0),
                false,
            ),
            (
                "嗯嗯 嗯好 嗯呐",
                "嗯.",
                Some(1),
                Some(100),
                None,
                None,
                Some(0),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(1),
                Some(1),
                Some(0),
                None,
                Some(1),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                Some(1),
                Some(1),
                Some(1),
                None,
                Some(4),
                false,
            ),
            (
                "嗯嗯 嗯好 嗯呐",
                "嗯.",
                Some(1),
                Some(1),
                Some(0),
                None,
                Some(1),
                false,
            ),
            (
                "嗯嗯 嗯好 嗯呐",
                "嗯.",
                Some(1),
                Some(1),
                Some(1),
                None,
                Some(3),
                false,
            ),
            ("", "^$", Some(1), Some(1), Some(0), None, Some(1), false),
            ("", "^$", Some(1), Some(1), Some(1), None, Some(1), false),
            (
                "abc",
                "ab.",
                Some(1),
                Some(1),
                Some(0),
                Some(""),
                Some(1),
                false,
            ),
            (
                "abc",
                "aB.",
                Some(1),
                Some(1),
                Some(0),
                Some("i"),
                Some(1),
                false,
            ),
            (
                "good\nday",
                "od$",
                Some(1),
                Some(1),
                Some(0),
                Some("m"),
                Some(3),
                false,
            ),
            (
                "good\nday",
                "oD$",
                Some(1),
                Some(1),
                Some(0),
                Some("mi"),
                Some(3),
                false,
            ),
            (
                "\n",
                ".",
                Some(1),
                Some(1),
                Some(0),
                Some("s"),
                Some(1),
                false,
            ),
        ];

        for (expr, pattern, pos, occur, ret_opt, match_type, expected, error) in cases {
            let mut ctx = EvalContext::default();

            let mut builder =
                ExprDefBuilder::scalar_func(ScalarFuncSig::RegexpInStrSig, FieldTypeTp::LongLong);
            builder = builder
                .push_child(ExprDefBuilder::constant_bytes(expr.as_bytes().to_vec()))
                .push_child(ExprDefBuilder::constant_bytes(pattern.as_bytes().to_vec()));
            if let Some(p) = pos {
                builder = builder.push_child(ExprDefBuilder::constant_int(p));
            }
            if let Some(o) = occur {
                builder = builder.push_child(ExprDefBuilder::constant_int(o));
            }
            if let Some(r) = ret_opt {
                builder = builder.push_child(ExprDefBuilder::constant_int(r));
            }
            if let Some(m) = match_type {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(m.as_bytes().to_vec()));
            }

            let node = builder.build();
            let exp = RpnExpressionBuilder::build_from_expr_tree(node, &mut ctx, 1).unwrap();

            let schema = &[];
            let mut columns = LazyBatchColumnVec::empty();

            let val = exp.eval(&mut ctx, schema, &mut columns, &[], 1);

            match val {
                Ok(val) => {
                    assert!(val.is_vector());
                    let v = val.vector_value().unwrap().as_ref().to_int_vec();
                    assert_eq!(v.len(), 1);
                    assert_eq!(v[0], expected, "{:?} {:?} {:?}", expr, pattern, pos);
                }
                Err(e) => {
                    assert!(error, "val has error {:?}", e);
                }
            }
        }

        // Test null
        let cases = vec![
            (None, Some("a"), Some(1), Some(1), Some(0), Some("i")),
            (Some("a"), None, Some(1), Some(1), Some(0), Some("i")),
            (Some("a"), Some("a"), None, Some(1), Some(0), Some("i")),
            (Some("a"), Some("a"), Some(1), None, Some(0), Some("i")),
            (Some("a"), Some("a"), Some(1), Some(1), None, Some("i")),
            (Some("a"), Some("a"), Some(1), Some(1), Some(0), None),
        ];
        for (expr, pattern, pos, occur, ret_opt, match_type) in cases {
            let mut ctx = EvalContext::default();

            let mut builder =
                ExprDefBuilder::scalar_func(ScalarFuncSig::RegexpInStrSig, FieldTypeTp::LongLong);
            if let Some(e) = expr {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(e.as_bytes().to_vec()));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::String));
            }
            if let Some(p) = pattern {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(p.as_bytes().to_vec()));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::String));
            }
            if let Some(p) = pos {
                builder = builder.push_child(ExprDefBuilder::constant_int(p));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::LongLong));
            }
            if let Some(o) = occur {
                builder = builder.push_child(ExprDefBuilder::constant_int(o));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::LongLong));
            }
            if let Some(r) = ret_opt {
                builder = builder.push_child(ExprDefBuilder::constant_int(r));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::LongLong));
            }
            if let Some(m) = match_type {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(m.as_bytes().to_vec()));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::String));
            }

            let node = builder.build();
            let exp = RpnExpressionBuilder::build_from_expr_tree(node, &mut ctx, 1).unwrap();

            let schema = &[];
            let mut columns = LazyBatchColumnVec::empty();

            let val = exp.eval(&mut ctx, schema, &mut columns, &[], 1).unwrap();
            assert!(val.is_vector());
            let v = val.vector_value().unwrap().as_ref().to_int_vec();
            assert_eq!(v.len(), 1);
            assert_eq!(v[0], None);
        }
    }

    #[test]
    fn test_regexp_replace() {
        let cases = vec![
            (
                "abc abd abe",
                "ab.",
                "cz",
                None,
                None,
                None,
                Some("cz cz cz"),
                false,
            ),
            (
                "你好 好的",
                "好",
                "逸",
                None,
                None,
                None,
                Some("你逸 逸的"),
                false,
            ),
            ("", "^$", "123", None, None, None, Some("123"), false),
            ("abc", "ab.", "cc", Some(1), None, None, Some("cc"), false),
            ("abc", "bc", "cc", Some(3), None, None, Some("abc"), false),
            ("你好", "好", "的", Some(2), None, None, Some("你的"), false),
            (
                "你好啊",
                "好",
                "的",
                Some(3),
                None,
                None,
                Some("你好啊"),
                false,
            ),
            ("", "^$", "cc", Some(1), None, None, Some("cc"), false),
            // Test invalid position index
            ("", "^$", "a", Some(2), None, None, None, true),
            ("", "^&", "a", Some(0), None, None, None, true),
            ("abc", "bc", "a", Some(-1), None, None, None, true),
            ("abc", "bc", "a", Some(4), None, None, None, true),
            (
                "abc abd",
                "ab.",
                "cc",
                Some(1),
                Some(1),
                None,
                Some("cc abd"),
                false,
            ),
            (
                "abc abd",
                "ab.",
                "cc",
                Some(1),
                Some(-1),
                None,
                Some("cc abd"),
                false,
            ),
            (
                "abc abd",
                "ab.",
                "cc",
                Some(1),
                Some(2),
                None,
                Some("abc cc"),
                false,
            ),
            (
                "abc abd",
                "ab.",
                "cc",
                Some(1),
                Some(0),
                None,
                Some("cc cc"),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                "cc",
                Some(1),
                Some(3),
                None,
                Some("abc abd cc"),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                "cc",
                Some(3),
                Some(2),
                None,
                Some("abc abd cc"),
                false,
            ),
            (
                "abc abd abe",
                "ab.",
                "cc",
                Some(3),
                Some(10),
                None,
                Some("abc abd abe"),
                false,
            ),
            (
                "你好 好啊",
                "好",
                "的",
                Some(1),
                Some(1),
                None,
                Some("你的 好啊"),
                false,
            ),
            (
                "你好 好啊",
                "好",
                "的",
                Some(3),
                Some(1),
                None,
                Some("你好 的啊"),
                false,
            ),
            ("", "^$", "cc", Some(1), Some(1), None, Some("cc"), false),
            ("", "^$", "cc", Some(1), Some(2), None, Some(""), false),
            ("", "^$", "cc", Some(1), Some(-1), None, Some("cc"), false),
            (
                "abc",
                "ab.",
                "cc",
                Some(1),
                Some(0),
                Some(""),
                Some("cc"),
                false,
            ),
            (
                "abc",
                "aB.",
                "cc",
                Some(1),
                Some(0),
                Some("i"),
                Some("cc"),
                false,
            ),
            (
                "good\nday",
                "od$",
                "cc",
                Some(1),
                Some(0),
                Some("m"),
                Some("gocc\nday"),
                false,
            ),
            (
                "good\nday",
                "oD$",
                "cc",
                Some(1),
                Some(0),
                Some("mi"),
                Some("gocc\nday"),
                false,
            ),
            (
                "\n",
                ".",
                "cc",
                Some(1),
                Some(0),
                Some("s"),
                Some("cc"),
                false,
            ),
            (
                "好的 好滴 好~",
                ".",
                "的",
                Some(1),
                Some(0),
                Some("msi"),
                Some("的的的的的的的的"),
                false,
            ),
            (
                r"abc",
                r"\d*",
                r"d",
                None,
                None,
                None,
                Some(r"dadbdcd"),
                false,
            ),
            // Test capture group
            (
                r"seafood fool",
                r"foo(.?)",
                r"123",
                Some(3),
                None,
                None,
                Some(r"sea123 123"),
                false,
            ),
            (
                r"seafood fool",
                r"foo(.?)",
                r"123",
                Some(5),
                None,
                None,
                Some(r"seafood 123"),
                false,
            ),
            (
                r"seafood fool",
                r"foo(.?)",
                r"z\12",
                Some(3),
                None,
                None,
                Some(r"seazd2 zl2"),
                false,
            ),
            (
                r"seafood fool",
                r"foo(.?)",
                r"z\12",
                Some(5),
                None,
                None,
                Some(r"seafood zl2"),
                false,
            ),
            (
                r"seafood fool",
                r"foo(.?)",
                r"z\12",
                Some(3),
                Some(0),
                None,
                Some(r"seazd2 zl2"),
                false,
            ),
            (
                r"seafood foo",
                r"foo(.?)",
                r"z\12",
                Some(3),
                Some(2),
                None,
                Some(r"seafood z2"),
                false,
            ),
            (
                r"stackoverflow",
                r"(.{5})(.*)",
                r"\\+\2+\1+\2+\1\",
                None,
                None,
                None,
                Some(r"\+overflow+stack+overflow+stack"),
                false,
            ),
            (
                r"fooabcdefghij fooABCDEFGHIJ",
                r"foo(.)(.)(.)(.)(.)(.)(.)(.)(.)(.)",
                r"\\\9\\\8-\7\\\6-\5\\\4-\3\\\2-\1\\",
                Some(1),
                Some(0),
                None,
                Some(r"\i\h-g\f-e\d-c\b-a\ \I\H-G\F-E\D-C\B-A\"),
                false,
            ),
            (
                r"fool food foo",
                r"foo(.?)",
                r"\0+\1",
                None,
                None,
                None,
                Some(r"fool+l food+d foo+"),
                false,
            ),
            // \2 is out of capture group's range.
            (
                r"fool food foo",
                r"foo(.?)",
                r"\0+\2",
                None,
                None,
                None,
                None,
                true,
            ),
            (
                r"https://go.mail/folder-1/online/ru-en/#lingvo/#1О 50000&price_ashka/rav4/page=/check.xml",
                r"^https?://(?:www\\.)?([^/]+)/.*$",
                r"a\12\13",
                None,
                None,
                None,
                Some(r"ago.mail2go.mail3"),
                false,
            ),
            (
                r"http://saint-peters-total=меньше 1000-rublyayusche/catalogue/kolasuryat-v-2-kadyirovka-personal/serial_id=0&input_state/apartments/mokrotochki.net/upravda.ru/yandex.ru/GameMain.aspx?mult]/on/orders/50195&text=мыс и орелка в Балаш смотреть онлайн бесплатно в хорошем камбалакс&lr=20030393833539353862643188&op_promo=C-Teaser_id=06d162.html",
                r"^https?://(?:www\\.)?([^/]+)/.*$",
                r"aaa\1233",
                None,
                None,
                None,
                Some(r"aaasaint-peters-total=меньше 1000-rublyayusche233"),
                false,
            ),
        ];

        for (expr, pattern, replace, pos, occur, match_type, expected, error) in cases {
            for i in 0..2 {
                let use_column_ref = i == 1;

                let mut ctx = EvalContext::default();

                let mut builder = ExprDefBuilder::scalar_func(
                    ScalarFuncSig::RegexpReplaceSig,
                    FieldTypeTp::String,
                );

                let mut schema = Vec::new();
                let mut columns = LazyBatchColumnVec::empty();
                if use_column_ref {
                    schema.extend_from_slice(&[
                        FieldTypeTp::String.into(),
                        FieldTypeTp::String.into(),
                        FieldTypeTp::String.into(),
                    ]);
                    builder = builder
                        .push_child(ExprDefBuilder::column_ref(0, FieldTypeTp::String))
                        .push_child(ExprDefBuilder::column_ref(1, FieldTypeTp::String))
                        .push_child(ExprDefBuilder::column_ref(2, FieldTypeTp::String));
                    let mut col_vec = Vec::new();
                    let mut col = LazyBatchColumn::decoded_with_capacity_and_tp(1, EvalType::Bytes);
                    col.mut_decoded().push_bytes(Some(expr.as_bytes().to_vec()));
                    col_vec.push(col);

                    let mut col = LazyBatchColumn::decoded_with_capacity_and_tp(1, EvalType::Bytes);
                    col.mut_decoded()
                        .push_bytes(Some(pattern.as_bytes().to_vec()));
                    col_vec.push(col);

                    let mut col = LazyBatchColumn::decoded_with_capacity_and_tp(1, EvalType::Bytes);
                    col.mut_decoded()
                        .push_bytes(Some(replace.as_bytes().to_vec()));
                    col_vec.push(col);

                    let mut count = 0;
                    if let Some(p) = pos {
                        count += 1;
                        schema.push(FieldTypeTp::Long.into());
                        let mut col =
                            LazyBatchColumn::decoded_with_capacity_and_tp(1, EvalType::Int);
                        col.mut_decoded().push_int(Some(p));
                        col_vec.push(col);

                        builder =
                            builder.push_child(ExprDefBuilder::column_ref(3, FieldTypeTp::Long));
                    }
                    if let Some(o) = occur {
                        assert_eq!(count, 1);
                        count += 1;
                        schema.push(FieldTypeTp::Long.into());
                        let mut col =
                            LazyBatchColumn::decoded_with_capacity_and_tp(1, EvalType::Int);
                        col.mut_decoded().push_int(Some(o));
                        col_vec.push(col);

                        builder =
                            builder.push_child(ExprDefBuilder::column_ref(4, FieldTypeTp::Long));
                    }
                    if let Some(m) = match_type {
                        assert_eq!(count, 2);
                        schema.push(FieldTypeTp::String.into());
                        let mut col =
                            LazyBatchColumn::decoded_with_capacity_and_tp(1, EvalType::Bytes);
                        col.mut_decoded().push_bytes(Some(m.as_bytes().to_vec()));
                        col_vec.push(col);

                        builder =
                            builder.push_child(ExprDefBuilder::column_ref(5, FieldTypeTp::String));
                    }

                    columns = LazyBatchColumnVec::from(col_vec);
                } else {
                    builder = builder
                        .push_child(ExprDefBuilder::constant_bytes(expr.as_bytes().to_vec()))
                        .push_child(ExprDefBuilder::constant_bytes(pattern.as_bytes().to_vec()))
                        .push_child(ExprDefBuilder::constant_bytes(replace.as_bytes().to_vec()));
                    let mut count = 0;
                    if let Some(p) = pos {
                        count += 1;
                        builder = builder.push_child(ExprDefBuilder::constant_int(p));
                    }
                    if let Some(o) = occur {
                        assert_eq!(count, 1);
                        count += 1;
                        builder = builder.push_child(ExprDefBuilder::constant_int(o));
                    }
                    if let Some(m) = match_type {
                        assert_eq!(count, 2);
                        builder = builder
                            .push_child(ExprDefBuilder::constant_bytes(m.as_bytes().to_vec()));
                    }
                }

                let node = builder.build();
                let exp = RpnExpressionBuilder::build_from_expr_tree(node, &mut ctx, schema.len())
                    .unwrap();

                let val = exp.eval(&mut ctx, &schema, &mut columns, &[0], 1);

                match val {
                    Ok(val) => {
                        assert!(val.is_vector());
                        let v = val.vector_value().unwrap().as_ref().to_bytes_vec();
                        assert_eq!(v.len(), 1);
                        assert_eq!(
                            v[0],
                            expected.map(|e| e.as_bytes().to_vec()),
                            "{:?} {:?} {:?}",
                            expr,
                            pattern,
                            replace,
                        );
                    }
                    Err(e) => {
                        assert!(error, "val has error {:?}", e);
                    }
                }
            }
        }

        // Test null
        let cases = vec![
            (None, Some("a"), Some("a"), Some(1), Some(0), Some("i")),
            (Some("a"), None, Some("a"), Some(1), Some(0), Some("i")),
            (Some("a"), Some("a"), None, Some(1), Some(0), Some("i")),
            (Some("a"), Some("a"), Some("a"), None, Some(0), Some("i")),
            (Some("a"), Some("a"), Some("a"), Some(1), None, Some("i")),
            (Some("a"), Some("a"), Some("a"), Some(1), Some(0), None),
        ];
        for (expr, pattern, replace, pos, occur, match_type) in cases {
            let mut ctx = EvalContext::default();

            let mut builder =
                ExprDefBuilder::scalar_func(ScalarFuncSig::RegexpReplaceSig, FieldTypeTp::String);
            if let Some(e) = expr {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(e.as_bytes().to_vec()));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::String));
            }
            if let Some(p) = pattern {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(p.as_bytes().to_vec()));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::String));
            }
            if let Some(r) = replace {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(r.as_bytes().to_vec()));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::String));
            }
            if let Some(p) = pos {
                builder = builder.push_child(ExprDefBuilder::constant_int(p));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::LongLong));
            }
            if let Some(o) = occur {
                builder = builder.push_child(ExprDefBuilder::constant_int(o));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::LongLong));
            }
            if let Some(m) = match_type {
                builder = builder.push_child(ExprDefBuilder::constant_bytes(m.as_bytes().to_vec()));
            } else {
                builder = builder.push_child(ExprDefBuilder::constant_null(FieldTypeTp::String));
            }

            let node = builder.build();
            let exp = RpnExpressionBuilder::build_from_expr_tree(node, &mut ctx, 1).unwrap();

            let schema = &[];
            let mut columns = LazyBatchColumnVec::empty();

            let val = exp.eval(&mut ctx, schema, &mut columns, &[], 1).unwrap();
            assert!(val.is_vector());
            let v = val.vector_value().unwrap().as_ref().to_bytes_vec();
            assert_eq!(v.len(), 1);
            assert_eq!(v[0], None);
        }
    }

    /// Evaluates a regexp `sig` over latin1_bin input, where bytes such as 0xFF
    /// or 0xE9 are valid characters. `check` inspects the single result value.
    fn eval_regexp_on_bytes<R>(
        sig: ScalarFuncSig,
        ret_tp: FieldTypeTp,
        expr: &[u8],
        pattern: &[u8],
        extra_int_args: &[i64],
        extra_bytes_args: &[&[u8]],
        check: impl FnOnce(&crate::types::RpnStackNodeVectorValue<'_>) -> R,
    ) -> R {
        let mut ctx = EvalContext::default();

        let mut builder = ExprDefBuilder::scalar_func(sig, ret_tp);
        builder = builder
            .push_child(ExprDefBuilder::constant_bytes(expr.to_vec()))
            .push_child(ExprDefBuilder::constant_bytes(pattern.to_vec()));
        for arg in extra_int_args {
            builder = builder.push_child(ExprDefBuilder::constant_int(*arg));
        }
        for arg in extra_bytes_args {
            builder = builder.push_child(ExprDefBuilder::constant_bytes(arg.to_vec()));
        }

        let mut node = builder.build();
        node.mut_field_type()
            .as_mut_accessor()
            .set_collation(Collation::Latin1Bin);

        let exp = RpnExpressionBuilder::build_from_expr_tree(node, &mut ctx, 1).unwrap();
        let schema = &[];
        let mut columns = LazyBatchColumnVec::empty();
        let val = exp.eval(&mut ctx, schema, &mut columns, &[], 1).unwrap();
        assert!(val.is_vector());
        check(val.vector_value().unwrap())
    }

    /// Regular expressions must not fail on non-UTF-8 bytes. TiDB evaluates
    /// them with Go's `regexp`, which decodes every malformed byte as one
    /// U+FFFD rune; a latin1 0xFF therefore matches `.` and the row is
    /// returned instead of an Utf8Error. See issue #20307.
    #[test]
    fn test_regexp_on_invalid_utf8() {
        // regexp_instr(expr, '.'): latin1 0xFF is one character, position 1.
        eval_regexp_on_bytes(
            ScalarFuncSig::RegexpInStrSig,
            FieldTypeTp::LongLong,
            &[0xFF],
            b".",
            &[],
            &[],
            |v| assert_eq!(v.as_ref().to_int_vec(), vec![Some(1)]),
        );

        // regexp_like(expr, '.'): the same match through the LIKE operator.
        eval_regexp_on_bytes(
            ScalarFuncSig::RegexpLikeSig,
            FieldTypeTp::LongLong,
            &[0xFF],
            b".",
            &[],
            &[],
            |v| assert_eq!(v.as_ref().to_int_vec(), vec![Some(1)]),
        );

        // regexp_substr reports the original bytes behind the match.
        eval_regexp_on_bytes(
            ScalarFuncSig::RegexpSubstrSig,
            FieldTypeTp::String,
            b"ab\xE9",
            b"b.",
            &[],
            &[],
            |v| assert_eq!(v.as_ref().to_bytes_vec(), vec![Some(b"b\xE9".to_vec())]),
        );

        // regexp_substr from a position after an invalid byte: positions
        // count characters, and the result keeps the original byte.
        eval_regexp_on_bytes(
            ScalarFuncSig::RegexpSubstrSig,
            FieldTypeTp::String,
            &[b'a', 0xFF, b'b', 0xE9],
            b".",
            &[2],
            &[],
            |v| assert_eq!(v.as_ref().to_bytes_vec(), vec![Some(vec![0xFF])]),
        );

        // regexp_instr counts every byte of a truncated multi-byte sequence as
        // one character, so "\xE4\xB8" has two characters and a `$` match at
        // its end is reported at position 3, like TiDB does.
        eval_regexp_on_bytes(
            ScalarFuncSig::RegexpInStrSig,
            FieldTypeTp::LongLong,
            &[0xE4, 0xB8],
            b"$",
            &[],
            &[],
            |v| assert_eq!(v.as_ref().to_int_vec(), vec![Some(3)]),
        );

        // Two latin1 characters match one by one: the second occurrence of "."
        // in "\xFF\xE9" starts at position 2.
        eval_regexp_on_bytes(
            ScalarFuncSig::RegexpInStrSig,
            FieldTypeTp::LongLong,
            &[0xFF, 0xE9],
            b".",
            &[1, 2],
            &[],
            |v| assert_eq!(v.as_ref().to_int_vec(), vec![Some(2)]),
        );

        // regexp_replace substitutes invalid bytes like any other character.
        eval_regexp_on_bytes(
            ScalarFuncSig::RegexpReplaceSig,
            FieldTypeTp::String,
            &[b'a', 0xFF, b'b'],
            b".",
            &[],
            &[b"X"],
            |v| assert_eq!(v.as_ref().to_bytes_vec(), vec![Some(b"XXX".to_vec())]),
        );
    }
}
