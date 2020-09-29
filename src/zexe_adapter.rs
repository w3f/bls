use pairing::curves::AffineCurve;
use pairing::curves::ProjectiveCurve;// as CurveProjective;
use pairing::fields::Field;
use std::error::Error;
use zexe_algebra::{PrimeField, SquareRootField};
use std::fmt;

use core::{
    ops::{Add, AddAssign, MulAssign, Neg, Sub, SubAssign},
};

/// Affine representation of an elliptic curve point that can be used
/// to perform pairings.
pub trait CurveAffine: AffineCurve + From<<Self as CurveAffine>::Projective> {
    type Projective: CurveProjective<Affine = Self, ScalarField = <Self as AffineCurve>::ScalarField, BaseField = <Self as AffineCurve>::BaseField>
        + From<Self>
        + Into<Self>
        + MulAssign<<Self as AffineCurve>::ScalarField>; // needed due to https://github.com/rust-lang/rust/issues/69640

    type Prepared: Clone + Send + Sync + 'static;
    type Pair: CurveAffine<Pair = Self>;
    type PairingResult: Field;

    type Uncompressed: EncodedPoint<Affine = Self>;
    type Compressed: EncodedPoint<Affine = Self>;
    
    /// Prepares this element for pairing purposes.
    fn prepare(&self) -> Self::Prepared;

    /// Perform a pairing
    fn pairing_with(&self, other: &Self::Pair) -> Self::PairingResult;
    
}

pub trait CurveProjective: ProjectiveCurve + From<<Self as CurveProjective>::Affine>
    + MulAssign<<Self as ProjectiveCurve>::ScalarField>
{
    type Affine: CurveAffine<Projective = Self, ScalarField = <Self as ProjectiveCurve>::ScalarField, BaseField = <Self as ProjectiveCurve>::BaseField>
        + From<Self>
        + Into<Self>;

    fn hash(msg: &[u8]) -> Self;

}

/// An encoded elliptic curve point, which should essentially wrap a `[u8; N]`.
pub trait EncodedPoint:
    Sized + Send + Sync + AsRef<[u8]> + AsMut<[u8]> + Clone + Copy + 'static
{
    type Affine: CurveAffine;

    /// Creates an empty representation.
    fn empty() -> Self;

    /// Returns the number of bytes consumed by this representation.
    fn size() -> usize;

    /// Converts an `EncodedPoint` into a `CurveAffine` element,
    /// if the encoding represents a valid element.
    fn into_affine(&self) -> Result<Self::Affine, GroupDecodingError>;

    /// Converts an `EncodedPoint` into a `CurveAffine` element,
    /// without guaranteeing that the encoding represents a valid
    /// element. This is useful when the caller knows the encoding is
    /// valid already.
    ///
    /// If the encoding is invalid, this can break API invariants,
    /// so caution is strongly encouraged.
    fn into_affine_unchecked(&self) -> Result<Self::Affine, GroupDecodingError>;

    /// Creates an `EncodedPoint` from an affine point, as long as the
    /// point is not the point at infinity.
    fn from_affine(affine: Self::Affine) -> Self;
}

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

/// An error that may occur when trying to interpret a `PrimeFieldRepr` as a
/// `PrimeField` element.
#[derive(Debug)]
pub enum PrimeFieldDecodingError {
    /// The encoded value is not in the field
    NotInField(String),
}


impl Error for PrimeFieldDecodingError {
    fn description(&self) -> &str {
        match *self {
            PrimeFieldDecodingError::NotInField(..) => "not an element of the field",
        }
    }
}

impl fmt::Display for PrimeFieldDecodingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            PrimeFieldDecodingError::NotInField(ref repr) => {
                write!(f, "{} is not an element of the field", repr)
            }
        }
    }
}

/// An "engine" is a collection of types (fields, elliptic curve groups, etc.)
/// with well-defined relationships. Specific relationships (for example, a
/// pairing-friendly curve) can be defined in a subtrait.
pub trait ScalarEngine: Sized + 'static + Clone {
    /// This is the scalar field of the engine's groups.
    type Fr: PrimeField + SquareRootField;
}
