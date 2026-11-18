//! Reduced request shapes. Values are never stored, only lengths and marker hits.

use serde::{Deserialize, Serialize};

use crate::format::StrippedUrl;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    None,
    Username,
    Password,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    AsTyped,
    Percent,
    JsonEscaped,
    Base64,
    Base64Url,
    Hex,
    Md5Hex,
    Md5Base64,
    Sha1Hex,
    Sha1Base64,
    Sha256Hex,
    Sha256Base64,
    Sha512Hex,
    Sha512Base64,
}

impl Encoding {
    pub fn is_digest(self) -> bool {
        self.digest_name().is_some()
    }

    pub fn digest_name(self) -> Option<&'static str> {
        match self {
            Self::Md5Hex | Self::Md5Base64 => Some("md5"),
            Self::Sha1Hex | Self::Sha1Base64 => Some("sha1"),
            Self::Sha256Hex | Self::Sha256Base64 => Some("sha256"),
            Self::Sha512Hex | Self::Sha512Base64 => Some("sha512"),
            Self::AsTyped
            | Self::Percent
            | Self::JsonEscaped
            | Self::Base64
            | Self::Base64Url
            | Self::Hex => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MarkerHit {
    pub role: Role,
    pub encoding: Encoding,
    /// True when the match is weak (the marker is shorter than `LOW_CONFIDENCE_BELOW` characters), so a reader treats it as a hint.
    pub low_confidence: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueKind {
    String,
    Number,
    Bool,
    Null,
    File,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValueShape {
    pub kind: ValueKind,
    /// Characters for a string value, bytes for a file.
    pub len: u32,
    pub markers: Vec<MarkerHit>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldShape {
    pub key: String,
    pub value: ValueShape,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JsonShape {
    Object { fields: Vec<JsonField> },
    Array { items: Vec<JsonShape> },
    Value { value: ValueShape },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonField {
    pub key: String,
    pub value: JsonShape,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BodyShape {
    None,
    Unavailable,
    Urlencoded {
        fields: Vec<FieldShape>,
    },
    Json {
        root: JsonShape,
    },
    Multipart {
        parts: Vec<FieldShape>,
    },
    Opaque {
        /// Bytes.
        len: u64,
        markers: Vec<MarkerHit>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthShape {
    pub scheme: String,
    pub markers: Vec<MarkerHit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Document,
    Xhr,
    Fetch,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponseShape {
    pub status: u16,
    pub content_type: Option<String>,
    pub set_cookie: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredRequest {
    /// Milliseconds since the recording started.
    pub t_ms: u64,
    pub method: String,
    pub url: StrippedUrl,
    pub resource: ResourceKind,
    pub main_frame_navigation: bool,
    pub content_type: Option<String>,
    pub authorization: Option<AuthShape>,
    pub url_markers: Vec<MarkerHit>,
    pub body: BodyShape,
    pub response: Option<ResponseShape>,
}

impl JsonShape {
    fn collect<'a>(&'a self, out: &mut Vec<&'a MarkerHit>) {
        match self {
            Self::Object { fields } => fields.iter().for_each(|f| f.value.collect(out)),
            Self::Array { items } => items.iter().for_each(|i| i.collect(out)),
            Self::Value { value } => out.extend(&value.markers),
        }
    }
}

impl StoredRequest {
    /// Every marker hit in the URL, the authorization header and every level of the body.
    pub fn hits(&self) -> Vec<&MarkerHit> {
        let mut out: Vec<&MarkerHit> = self.url_markers.iter().collect();
        if let Some(auth) = &self.authorization {
            out.extend(&auth.markers);
        }
        match &self.body {
            BodyShape::None | BodyShape::Unavailable => {}
            BodyShape::Urlencoded { fields } | BodyShape::Multipart { parts: fields } => {
                out.extend(fields.iter().flat_map(|f| &f.value.markers));
            }
            BodyShape::Json { root } => root.collect(&mut out),
            BodyShape::Opaque { markers, .. } => out.extend(markers),
        }
        out
    }
}
