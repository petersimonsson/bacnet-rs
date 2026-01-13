/// Generates a Rust enum with a custom range of values, including variants for
/// named values, custom values within a specified range, and reserved values
/// outside that range.
///
/// This macro is particularly useful for creating BACnet-related enums where
/// standard values are enumerated, but custom or proprietary values might also
/// exist within or outside a defined range.
///
/// # Arguments
///
/// * `$name:ident` - The name of the enum to be generated.
/// * `$variant:ident = $value:expr` - A comma-separated list of named enum
///   variants and their corresponding integer values.
/// * `$unit:ident` - The underlying integer type for the enum (e.g., `u8`, `u16`, `u32`).
/// * `$range:expr` - An expression representing the valid custom range (e.g., `1000..=2000`).
///   Values within this range that are not explicitly named variants will be
///   represented by the `Custom` variant.
///
/// # Example
///
/// ```rust
/// use bacnet_rs::generate_custom_enum;
///
/// generate_custom_enum! {
///     MyEnum {
///         VariantA = 1,
///         VariantB = 2,
///         VariantC = 100,
///     },
///     u16,
///     1000..=2000
/// }
///
/// // Usage
/// let a = MyEnum::VariantA;
/// let custom_val = MyEnum::from(1500u16); // Will be MyEnum::Custom{ value: 1500 }
/// let reserved_val = MyEnum::from(3000u16); // Will be MyEnum::Reserved{ value: 3000 }
/// let named_val = MyEnum::from(100u16); // Will be MyEnum::VariantC
///
/// assert_eq!(u16::from(a), 1);
/// assert_eq!(format!("{}", a), "VariantA");
/// assert_eq!(custom_val, MyEnum::Custom{ value: 1500 });
/// assert_eq!(reserved_val, MyEnum::Reserved{ value: 3000 });
/// assert_eq!(named_val, MyEnum::VariantC);
/// ```
///
/// # Generated Code Structure
///
/// The macro generates an enum with the following variants:
///
/// * `$(variant:ident),*` - The named variants provided by the user.
/// * `Custom { value: $unit }` - Represents values within the specified `$range`
///   that do not correspond to any named variant.
/// * `Reserved { value: $unit }` - Represents values outside the specified
///   `$range` (and not named variants).
///
/// It also implements:
///
/// * `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash` for the enum.
/// * `std::fmt::Display` for human-readable string representation.
///   - Named variants display their name.
///   - `Custom` variants display as `Custom(value)`.
///   - `Reserved` variants display as `Reserved(value)`.
/// * `From<$name> for $unit` for easy conversion from the enum to its underlying integer type.
/// * `From<$unit> for $name` for easy conversion from the underlying integer type to the enum,
///   handling named, custom, and reserved values appropriately based on the `$range`.
#[macro_export]
macro_rules! generate_custom_enum {
    ($(#[$doc:meta])* $name:ident { $($variant:ident = $value:expr,)* }, $unit:ident, $range:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant,)*
            Custom{ value: $unit },
            Reserved{ value: $unit },
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $($name::$variant => write!(f, "{}", stringify!($variant)),)*
                    $name::Custom{ value } => write!(f, "Custom({})", value),
                    $name::Reserved{ value } => write!(f, "Reserved({})", value),
                }
            }
        }

        impl From<$name> for $unit {
            fn from(value: $name) -> Self {
                match value {
                    $($name::$variant => $value,)*
                    $name::Custom{ value } => value,
                    $name::Reserved{ value } => value,
                }
            }
        }

        impl From<$unit> for $name {
            fn from(value: $unit) -> Self {
                match value {
                    $($value => $name::$variant,)*
                    v if $range.contains(&v) => $name::Custom{ value: v },
                    v => $name::Reserved{ value: v },
                }
            }
        }
    };
}
