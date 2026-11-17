// Copyright 2017 TiKV Project Authors. Licensed under Apache-2.0.

use std::collections::BTreeMap;

use super::{Json, JsonRef, JsonType};
use crate::codec::Result;

impl Json {
    /// `merge` is the implementation for JSON_MERGE in mysql
    /// <https://dev.mysql.com/doc/refman/5.7/en/json-modification-functions.html#function_json-merge>
    ///
    /// The merge rules are listed as following:
    /// 1. adjacent arrays are merged to a single array;
    /// 2. adjacent object are merged to a single object;
    /// 3. a scalar value is autowrapped as an array before merge;
    /// 4. an adjacent array and object are merged by autowrapping the object as
    ///    an array.
    ///
    /// See `MergeBinary()` in TiDB `json/binary_function.go`
    #[allow(clippy::comparison_chain)]
    pub fn merge(bjs: Vec<JsonRef<'_>>) -> Result<Json> {
        let mut result = vec![];
        let mut objects = vec![];
        for j in bjs {
            if j.get_type() != JsonType::Object {
                if objects.len() == 1 {
                    let o = objects.pop().unwrap();
                    result.push(MergeUnit::Ref(o));
                } else if objects.len() > 1 {
                    // We have adjacent JSON objects, merge them into a single object
                    result.push(MergeUnit::Owned(merge_binary_object(&mut objects)?));
                }
                result.push(MergeUnit::Ref(j));
            } else {
                objects.push(j);
            }
        }
        // Resolve the possibly remained objects
        if !objects.is_empty() {
            result.push(MergeUnit::Owned(merge_binary_object(&mut objects)?));
        }
        if result.len() == 1 {
            return Ok(result.pop().unwrap().into_owned());
        }
        merge_binary_array(&result)
    }

    #[allow(clippy::comparison_chain)]
    // See `mergePatchBinaryJSON()` in TiDB `pkg/types/json_binary_functions.go`
    pub fn merge_patch(target: JsonRef<'_>, patch: JsonRef<'_>) -> Result<Json> {
        if patch.get_type() != JsonType::Object {
            Ok(patch.to_owned())
        } else {
            // Object keys are not necessarily valid UTF-8 (e.g. a latin1 key
            // inserted by `JSON_OBJECT(_latin1 X'FF', 1)` in TiDB), so they are
            // kept as raw bytes here, like TiDB does with `string(key)`.
            // See <https://github.com/tikv/tikv/issues/20313>
            let mut key_val_map: BTreeMap<Vec<u8>, Json> = BTreeMap::new();
            if target.get_type() == JsonType::Object {
                let elem_count = target.get_elem_count();
                for i in 0..elem_count {
                    let key = target.object_get_key(i);
                    let val = target.object_get_val(i)?;
                    key_val_map.insert(key.to_owned(), val.to_owned());
                }
            }

            let mut tmp: Json;
            let elem_count = patch.get_elem_count();
            for i in 0..elem_count {
                let key = patch.object_get_key(i).to_owned();
                let val = patch.object_get_val(i)?;

                if val.get_type() == JsonType::Literal && val.get_literal().is_none() {
                    key_val_map.remove(&key);
                } else {
                    let target_kv = key_val_map.get(&key);
                    if let Some(target_kv) = target_kv {
                        tmp = Self::merge_patch(target_kv.as_ref(), val)?;
                    } else {
                        tmp = Self::merge_patch(Json::from_bool(false).unwrap().as_ref(), val)?;
                    }
                    key_val_map.insert(key, tmp);
                }
            }
            Json::from_object_map(key_val_map)
        }
    }
}

enum MergeUnit<'a> {
    Ref(JsonRef<'a>),
    Owned(Json),
}

impl MergeUnit<'_> {
    fn as_ref(&self) -> JsonRef<'_> {
        match self {
            MergeUnit::Ref(r) => *r,
            MergeUnit::Owned(o) => o.as_ref(),
        }
    }
    fn into_owned(self) -> Json {
        match self {
            MergeUnit::Ref(r) => r.to_owned(),
            MergeUnit::Owned(o) => o,
        }
    }
}

// See `mergeBinaryArray()` in TiDB `json/binary_function.go`
fn merge_binary_array(elems: &[MergeUnit<'_>]) -> Result<Json> {
    let mut buf = vec![];
    for j in elems.iter() {
        let j = j.as_ref();
        if j.get_type() != JsonType::Array {
            buf.push(j)
        } else {
            let child_count = j.get_elem_count();
            for i in 0..child_count {
                buf.push(j.array_get_elem(i)?);
            }
        }
    }
    Json::from_ref_array(buf)
}

// See `mergeBinaryObject()` in TiDB `json/binary_function.go`
fn merge_binary_object(objects: &mut Vec<JsonRef<'_>>) -> Result<Json> {
    let mut kv_map: BTreeMap<Vec<u8>, Json> = BTreeMap::new();
    for j in objects.drain(..) {
        let elem_count = j.get_elem_count();
        for i in 0..elem_count {
            let key = j.object_get_key(i).to_owned();
            let val = j.object_get_val(i)?;
            if let Some(old) = kv_map.remove(&key) {
                let new = Json::merge(vec![old.as_ref(), val])?;
                kv_map.insert(key, new);
            } else {
                kv_map.insert(key, val.to_owned());
            }
        }
    }
    Json::from_object_map(kv_map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_patch() {
        // See `mergePatchBinaryJSON()` in TiDB `pkg/types/json_binary_functions.go`
        let cases = vec![
            (r#"{"a": 1}"#, r#"{"b": 2}"#, r#"{"a": 1, "b": 2}"#),
            (r#"{"a": 1}"#, r#"{"a": 2}"#, r#"{"a": 2}"#),
            (
                r#"{"a": 1, "b": {"c": 2}}"#,
                r#"{"b": {"d": 3}}"#,
                r#"{"a": 1, "b": {"c": 2, "d": 3}}"#,
            ),
            (r#"{"a": 1}"#, r#"{"a": null}"#, r#"{}"#),
            (r#"{"a": 1}"#, r#"{}"#, r#"{"a": 1}"#),
            (r#"{}"#, r#"{"a": 1}"#, r#"{"a": 1}"#),
            (r#"{"a": 1}"#, r#"null"#, r#"null"#),
            (r#"{"a": 1}"#, r#"4"#, r#"4"#),
            (r#"4"#, r#"{"a": 1}"#, r#"{"a": 1}"#),
        ];
        for case in cases {
            let (target, patch, expect) = case;
            let target = target.parse::<Json>().unwrap();
            let patch = patch.parse::<Json>().unwrap();
            let expect = expect.parse::<Json>().unwrap();
            let res = Json::merge_patch(target.as_ref(), patch.as_ref()).unwrap();
            assert_eq!(res, expect);
        }
    }

    /// Tests that a JSON object key which is not valid UTF-8 (e.g. the latin1
    /// byte 0xFF produced by TiDB via `JSON_OBJECT(_latin1 X'FF', 1)`) can be
    /// merged instead of failing with "encoding failed".
    /// See <https://github.com/tikv/tikv/issues/20313>
    #[test]
    fn test_merge_patch_with_invalid_utf8_key() {
        let target = r#"{}"#.parse::<Json>().unwrap();
        // `JSON_OBJECT(_latin1 X'FF', 1)` in TiDB keeps the raw latin1 byte
        // 0xFF as the object key, which is not valid UTF-8.
        let patch =
            Json::from_kv_pairs(vec![(b"\xFF", Json::from_i64(1).unwrap().as_ref())]).unwrap();

        let res = Json::merge_patch(target.as_ref(), patch.as_ref()).unwrap();
        // The key should be kept unchanged, like TiDB does with `string(key)`.
        let expected =
            Json::from_kv_pairs(vec![(b"\xFF", Json::from_i64(1).unwrap().as_ref())]).unwrap();
        assert_eq!(res, expected);

        // Merging the other way around: the non-UTF-8 key is in the target.
        let res = Json::merge_patch(patch.as_ref(), target.as_ref()).unwrap();
        assert_eq!(res, expected);

        // Removing the non-UTF-8 key via a null patch value.
        let null_patch =
            Json::from_kv_pairs(vec![(b"\xFF", Json::none().unwrap().as_ref())]).unwrap();
        let res = Json::merge_patch(expected.as_ref(), null_patch.as_ref()).unwrap();
        let empty = Json::from_kv_pairs(vec![]).unwrap();
        assert_eq!(res, empty);

        // JSON_MERGE (`merge_binary_object`) has the same issue.
        let jsons = [target, patch];
        let refs = jsons.iter().map(|j| j.as_ref()).collect::<Vec<_>>();
        let res = Json::merge(refs).unwrap();
        assert_eq!(res, expected);
    }

    #[test]
    fn test_merge() {
        let test_cases = vec![
            vec![r#"{"a": 1}"#, r#"{"b": 2}"#, r#"{"a": 1, "b": 2}"#],
            vec![r#"{"a": 1}"#, r#"{"a": 2}"#, r#"{"a": [1, 2]}"#],
            vec![r#"{"a": 1}"#, r#"{"a": [2, 3]}"#, r#"{"a": [1, 2, 3]}"#],
            vec![
                r#"{"a": 1}"#,
                r#"{"a": {"b": [2, 3]}}"#,
                r#"{"a": [1, {"b": [2, 3]}]}"#,
            ],
            vec![
                r#"{"a": {"b": [2, 3]}}"#,
                r#"{"a": 1}"#,
                r#"{"a": [{"b": [2, 3]}, 1]}"#,
            ],
            vec![
                r#"{"a": [1, 2]}"#,
                r#"{"a": {"b": [3, 4]}}"#,
                r#"{"a": [1, 2, {"b": [3, 4]}]}"#,
            ],
            vec![
                r#"{"b": {"c": 2}}"#,
                r#"{"a": 1, "b": {"d": 1}}"#,
                r#"{"a": 1, "b": {"c": 2, "d": 1}}"#,
            ],
            vec![r#"[1]"#, r#"[2]"#, r#"[1, 2]"#],
            vec![r#"{"a": 1}"#, r#"[1]"#, r#"[{"a": 1}, 1]"#],
            vec![r#"[1]"#, r#"{"a": 1}"#, r#"[1, {"a": 1}]"#],
            vec![r#"{"a": 1}"#, r#"4"#, r#"[{"a": 1}, 4]"#],
            vec![r#"[1]"#, r#"4"#, r#"[1, 4]"#],
            vec![r#"4"#, r#"{"a": 1}"#, r#"[4, {"a": 1}]"#],
            vec![r#"1"#, r#"[4]"#, r#"[1, 4]"#],
            vec![r#"4"#, r#"1"#, r#"[4, 1]"#],
            vec!["1", "2", "3", "[1, 2, 3]"],
            vec!["[1, 2]", "3", "[4, 5, 6]", "[1, 2, 3, 4, 5, 6]"],
            vec![
                r#"{"a": 1, "b": {"c": 3, "d": 4}, "e": [5, 6]}"#,
                r#"{"c": 7, "b": {"a": 8, "c": 9}, "f": [1, 2]}"#,
                r#"{"d": 9, "b": {"b": 10, "c": 11}, "e": 8}"#,
                r#"{
                    "a": 1,
                    "b": {"a": 8, "b": 10, "c": [3, 9, 11], "d": 4},
                    "c": 7,
                    "d": 9,
                    "e": [5, 6, 8],
                    "f": [1, 2]
                }"#,
            ],
        ];
        for case in test_cases {
            let (to_be_merged, expect) = case.split_at(case.len() - 1);
            let jsons = to_be_merged
                .iter()
                .map(|s| s.parse::<Json>().unwrap())
                .collect::<Vec<Json>>();
            let refs = jsons.iter().map(|j| j.as_ref()).collect::<Vec<_>>();
            let res = Json::merge(refs).unwrap();
            let expect: Json = expect[0].parse().unwrap();
            assert_eq!(res, expect);
        }
    }
}
