/// An error that may occur when trying to decode an `EncodedPoint`.
#[derive(thiserror::Error, Debug)]
pub enum GroupDecodingError {
    /// The coordinate(s) do not lie on the curve.
    #[error("coordinate(s) do not lie on the curve")]
    NotOnCurve,
    /// The element is not part of the r-order subgroup.
    #[error("the element is not part of an r-order subgroup")]
    NotInSubgroup,

    /// One of the coordinates could not be decoded
    #[error("coordinate(s) could not be decoded")]
    CoordinateDecodingError(&'static str, #[source] PrimeFieldDecodingError),
    /// The compression mode of the encoded element was not as expected
    #[error("encoding has unexpected compression mode")]
    UnexpectedCompressionMode,
    /// The encoding contained bits that should not have been set
    #[error("encoding has unexpected information")]
    UnexpectedInformation,
}
