//! Minimal JSON-RPC 2.0 message classification for MCP.

use serde_json::{Value, json};

/// A classified JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Request { id: Value, method: String, params: Option<Value> },
    Notification { method: String, params: Option<Value> },
    Response { id: Value, result: Option<Value>, error: Option<Value> },
}

impl Message {
    /// Classifies one JSON value. Returns `None` for anything that is not a
    /// JSON-RPC object.
    pub fn classify(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        let method = obj.get("method").and_then(Value::as_str);
        let id = obj.get("id").filter(|i| !i.is_null()).cloned();
        match (method, id) {
            (Some(m), Some(id)) => Some(Self::Request { id, method: m.to_string(), params: obj.get("params").cloned() }),
            (Some(m), None) => Some(Self::Notification { method: m.to_string(), params: obj.get("params").cloned() }),
            (None, Some(id)) if obj.contains_key("result") || obj.contains_key("error") => {
                Some(Self::Response { id, result: obj.get("result").cloned(), error: obj.get("error").cloned() })
            }
            _ => None,
        }
    }

    /// Parses a line (or HTTP body) that may hold a single message or a
    /// batch array. Invalid JSON yields an empty list.
    pub fn parse_all(bytes: &[u8]) -> Vec<(Value, Self)> {
        let Ok(v) = serde_json::from_slice::<Value>(trim_ascii(bytes)) else {
            return Vec::new();
        };
        match v {
            Value::Array(items) => items.into_iter().filter_map(|i| Self::classify(&i).map(|m| (i, m))).collect(),
            other => Self::classify(&other).map(|m| vec![(other, m)]).unwrap_or_default(),
        }
    }
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !c.is_ascii_whitespace()).map_or(start, |e| e + 1);
    &b[start..end]
}

/// Key used to match responses to requests (ids may be numbers or strings).
pub fn id_key(id: &Value) -> String {
    match id {
        Value::String(s) => format!("s:{s}"),
        other => format!("n:{other}"),
    }
}

/// JSON-RPC error code used when Rousseau blocks a call (implementation
/// defined server-error range).
pub const BLOCKED_ERROR_CODE: i64 = -32001;

/// Builds the error response returned to the client for a blocked call.
pub fn blocked_response(id: &Value, message: &str, reason: &str, data: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": BLOCKED_ERROR_CODE,
            "message": message,
            "data": { "rousseau": { "reason": reason, "details": data } }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_all_kinds() {
        let r = Message::classify(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}})).unwrap();
        assert!(matches!(r, Message::Request { ref method, .. } if method == "tools/call"));
        let n = Message::classify(&json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"})).unwrap();
        assert!(matches!(n, Message::Notification { .. }));
        let s = Message::classify(&json!({"jsonrpc":"2.0","id":"a","result":{}})).unwrap();
        assert!(matches!(s, Message::Response { .. }));
        let e = Message::classify(&json!({"jsonrpc":"2.0","id":2,"error":{"code":-1}})).unwrap();
        assert!(matches!(e, Message::Response { error: Some(_), .. }));
        assert!(Message::classify(&json!({"id":3})).is_none());
        assert!(Message::classify(&json!([1])).is_none());
    }

    #[test]
    fn parse_batches_and_garbage() {
        assert_eq!(Message::parse_all(b"  {\"id\":1,\"method\":\"ping\"}\r\n").len(), 1);
        assert_eq!(Message::parse_all(b"[{\"id\":1,\"method\":\"a\"},{\"method\":\"b\"},5]").len(), 2);
        assert!(Message::parse_all(b"not json").is_empty());
        assert!(Message::parse_all(b"").is_empty());
    }

    #[test]
    fn ids_and_block() {
        assert_ne!(id_key(&json!(1)), id_key(&json!("1")));
        let b = blocked_response(&json!(7), "no", "tool_drift", json!({"tool":"t"}));
        assert_eq!(b["error"]["code"], BLOCKED_ERROR_CODE);
        assert_eq!(b["id"], 7);
        assert_eq!(b["error"]["data"]["rousseau"]["reason"], "tool_drift");
    }
}
