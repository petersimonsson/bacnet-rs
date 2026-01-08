use bacnet_macros::BacnetEnum;

#[test]
fn test_bacnet_enum_derive() {
    #[derive(BacnetEnum, Debug, PartialEq, Eq)]
    #[bacnet_enum(u32)]
    enum TestEnum {
        #[bacnet_value(0)]
        Variant0,
        #[bacnet_value(1)]
        Variant1,
        #[bacnet_value(2)]
        Variant2,
    }

    assert_eq!(u32::from(TestEnum::Variant0), 0);
    assert_eq!(u32::from(TestEnum::Variant1), 1);
    assert_eq!(u32::from(TestEnum::Variant2), 2);

    assert_eq!(TestEnum::from(0), TestEnum::Variant0);
    assert_eq!(TestEnum::from(1), TestEnum::Variant1);
    assert_eq!(TestEnum::from(2), TestEnum::Variant2);

    assert_eq!(TestEnum::Variant0.to_string(), "Variant0");
    assert_eq!(TestEnum::Variant1.to_string(), "Variant1");
    assert_eq!(TestEnum::Variant2.to_string(), "Variant2");
}

#[test]
fn test_bacnet_enum_custom_variant() {
    #[derive(BacnetEnum, Debug, PartialEq, Eq)]
    #[bacnet_enum(u32)]
    enum TestEnumWithCustom {
        #[bacnet_value(10)]
        Ten,
        #[bacnet_value(20)]
        Twenty,
        Custom(u32),
    }

    // Test From<Enum> for u32
    assert_eq!(u32::from(TestEnumWithCustom::Ten), 10);
    assert_eq!(u32::from(TestEnumWithCustom::Twenty), 20);
    assert_eq!(u32::from(TestEnumWithCustom::Custom(99)), 99);

    // Test From<u32> for Enum
    assert_eq!(TestEnumWithCustom::from(10), TestEnumWithCustom::Ten);
    assert_eq!(TestEnumWithCustom::from(20), TestEnumWithCustom::Twenty);
    assert_eq!(TestEnumWithCustom::from(50), TestEnumWithCustom::Custom(50));
    assert_eq!(TestEnumWithCustom::from(0), TestEnumWithCustom::Custom(0));

    // Test Display
    assert_eq!(TestEnumWithCustom::Ten.to_string(), "Ten");
    assert_eq!(TestEnumWithCustom::Twenty.to_string(), "Twenty");
    assert_eq!(TestEnumWithCustom::Custom(123).to_string(), "Custom(123)");
}
