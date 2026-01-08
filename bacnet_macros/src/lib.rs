extern crate proc_macro;

use quote::quote;

#[proc_macro_derive(BacnetEnum, attributes(bacnet_enum, bacnet_value))]
pub fn derive_bacnet_enum(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let mut input = syn::parse_macro_input!(input as syn::DeriveInput);

    let name = &input.ident;
    let data = match &mut input.data {
        syn::Data::Enum(data) => data,
        _ => panic!("BacnetEnum can only be derived for enums"),
    };

    let unit = match input
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("bacnet_enum"))
    {
        Some(attr) => match attr.parse_args::<syn::Type>() {
            Ok(unit) => unit,
            Err(_) => panic!("BacnetEnum requires a type"),
        },
        None => panic!("BacnetEnum requires a type"),
    };

    let mut enum_to_unit = Vec::new();
    let mut unit_to_enum = Vec::new();
    let mut display_names = Vec::new();

    let mut custom_variant_found = false;
    for variant in data.variants.iter() {
        // Iterate over `data.variants` by reference
        let variant_name = &variant.ident;
        let name_str = variant_name.to_string();

        if variant_name == "Custom" {
            // Check if Custom variant has exactly one unnamed field
            if let syn::Fields::Unnamed(fields) = &variant.fields {
                if fields.unnamed.len() == 1 {
                    custom_variant_found = true;
                    // For From<#name> for #unit
                    enum_to_unit.push(quote! {
                        #name::Custom(val) => val,
                    });
                    // For Display
                    display_names.push(quote! {
                        #name::Custom(val) => write!(f, "Custom({})", val),
                    });
                } else {
                    panic!("Custom variant must have exactly one unnamed field.");
                }
            } else {
                panic!("Custom variant must have exactly one unnamed field of the unit type.");
            }
        } else {
            let bacnet_value = match variant
                .attrs
                .iter()
                .find(|attr| attr.path().is_ident("bacnet_value"))
            {
                Some(attr) => match attr.parse_args::<syn::LitInt>() {
                    Ok(v) => v,
                    Err(_) => panic!(
                        "BacnetEnum requires a value for each variant with `bacnet_value` attribute"
                    ),
                },
                None => panic!(
                    "BacnetEnum requires a `bacnet_value` attribute for variant `{}`",
                    variant_name
                ),
            };

            enum_to_unit.push(quote! {
                #name::#variant_name => #bacnet_value,
            });
            unit_to_enum.push(quote! {
                #bacnet_value => #name::#variant_name,
            });
            display_names.push(quote! {
                #name::#variant_name => write!(f, "{}", #name_str),
            });
        }
    }

    let unit_to_enum_wildcard = if custom_variant_found {
        quote! {
            val => #name::Custom(val),
        }
    } else {
        quote! {
            _ => panic!("Invalid value"),
        }
    };

    let expanded = quote! {
        use std::fmt::{Display, Formatter};

        impl From<#name> for #unit {
            fn from(val: #name) -> Self {
                match val {
                    #(#enum_to_unit)*
                }
            }
        }

        impl From<#unit> for #name {
            fn from(val: #unit) -> Self {
                match val {
                    #(#unit_to_enum)*
                    #unit_to_enum_wildcard
                }
            }
        }

        impl Display for #name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                match self {
                    #(#display_names)*
                }
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}
