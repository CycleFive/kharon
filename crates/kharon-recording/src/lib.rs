//! Typed recording format for kharon teach mode (#361).

pub mod classify;
pub mod format;
pub mod request;

pub use classify::{
    Classification, Flags, PasswordLeg, RungCeiling, Shape, classify, is_otp_descriptor,
};
pub use format::{
    BrowserInfo, ElementDescriptor, EndedBy, FORMAT_VERSION, FormRef, FormatError, FrameRef,
    ListenerWorld, Recording, Step, StrippedCounts, StrippedUrl, Viewport,
};
pub use request::{
    AuthShape, BodyShape, Deciding, Encoding, FieldShape, JsonField, JsonShape, MarkerHit,
    ResourceKind, ResponseShape, Role, StoredRequest, ValueKind, ValueShape,
};
