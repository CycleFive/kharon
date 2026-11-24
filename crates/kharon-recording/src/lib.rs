//! Typed recording format for kharon teach mode (#361).

pub mod classify;
pub mod format;
pub mod method;
pub mod request;

pub use classify::{
    Classification, Flags, PasswordLeg, RungCeiling, Shape, classify, is_otp_descriptor,
};
pub use format::{
    BrowserInfo, ElementDescriptor, EndedBy, FORMAT_VERSION, FormRef, FormatError, FrameRef,
    ListenerWorld, Recording, Step, StrippedCounts, StrippedUrl, Viewport,
};
pub use method::{
    ConvertOptions, Expected, FillRole, Leg, LoginMethod, METHOD_FILE_SUFFIX,
    METHOD_FORMAT_VERSION, MethodError, MethodStep, NotConvertible, Provenance, Rung, Site,
    SubmitVia, SuccessCheck, SuccessOverride,
};
pub use request::{
    AuthShape, BodyShape, Deciding, Encoding, FieldShape, JsonField, JsonShape, MarkerHit,
    ResourceKind, ResponseShape, Role, StoredRequest, ValueKind, ValueShape,
};
