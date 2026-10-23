//! Unit tests for the Lance codec edge: container detection, legacy and
//! structural page grammars, and round-trips through the normalized IR.

use super::*;
use crate::binary_ir::MapEntry;
use crate::binary_pump::{BinaryTransform, EnvelopeBinaryTransform};
use crate::binary_reductor::CommonTypeBinaryReductor;
use crate::hybrid::generate_keypair;

/// Reference-implementation fixture: a pylance-written Lance v2.0 file with
/// every supported legacy page shape (flat, nullable, binary, list, nested
/// list, fixed-size list, struct, bool, date, timestamp, decimal).
const MIXED_V2_0: &[u8] = include_bytes!("../../tests/fixtures/lance/mixed_v2_0.lance");
/// Reference-implementation fixture: a pylance-written Lance v2.2 file using
/// structural mini-block pages.
const INT_V2_2: &[u8] = include_bytes!("../../tests/fixtures/lance/int_v2_2.lance");
/// Reference-implementation fixture: a Lance v1 file (legacy container, rejected
/// by decoding after conservative detection recognizes it).
const INT_V1: &[u8] = include_bytes!("../../tests/fixtures/lance/int_v1.lance");

fn ir_record(fields: Vec<(&str, Value)>) -> ValueIr {
    ValueIr::new(Value::Record {
        fields: fields
            .into_iter()
            .map(|(name, value)| ValueField {
                name: name.to_string(),
                value,
            })
            .collect(),
    })
}

fn decode_all(bytes: &[u8]) -> (SchemaIr, Vec<ValueIr>) {
    let mut values = Vec::new();
    let schema = decode_lance(bytes, LanceLimits::default(), |value| {
        values.push(value);
        Ok(())
    })
    .unwrap();
    (schema, values)
}

fn round_trip(schema: &SchemaIr, values: &[ValueIr]) -> (SchemaIr, Vec<ValueIr>) {
    let encoded = encode_lance(schema, values, LanceLimits::default()).unwrap();
    assert!(
        encoded.ends_with(LANCE_MAGIC),
        "encoded Lance output must end with the LANC magic"
    );
    decode_all(&encoded)
}

fn string_schema() -> SchemaIr {
    SchemaIr::new(SchemaNode::required(SchemaKind::Record {
        fields: vec![SchemaField {
            name: "x".to_string(),
            schema: SchemaNode::required(SchemaKind::String),
        }],
    }))
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

#[test]
fn magic_footer_accepts_the_reference_layout() {
    let footer = validate_magic_footer(MIXED_V2_0).unwrap();
    assert_eq!(footer.num_global_buffers, 1);
    assert_eq!(footer.num_columns, 17);
    assert_eq!((footer.major_version, footer.minor_version), (0, 3));
}

#[test]
fn magic_footer_accepts_structural_v2_2_files() {
    let footer = validate_magic_footer(INT_V2_2).unwrap();
    assert_eq!((footer.major_version, footer.minor_version), (2, 2));
}

#[test]
fn magic_footer_rejects_truncated_files() {
    for len in [0, 4, LANCE_FOOTER_LEN - 1, MIXED_V2_0.len() - 1] {
        assert!(
            validate_magic_footer(&MIXED_V2_0[..len]).is_err(),
            "length {len} must be rejected"
        );
    }
}

#[test]
fn magic_footer_rejects_wrong_tail_magic() {
    let mut tampered = MIXED_V2_0.to_vec();
    let len = tampered.len();
    tampered[len - 1] ^= 0xFF;
    assert!(validate_magic_footer(&tampered).is_err());
}

#[test]
fn magic_footer_rejects_legacy_v1_containers() {
    // The v1 fixture carries the (0, 2) version pair: recognized as Lance,
    // rejected before any decoding happens.
    let error = validate_magic_footer(INT_V1).unwrap_err();
    assert_eq!(error.code(), codes::UNSUPPORTED_FORMAT);
}

#[test]
fn magic_footer_rejects_unknown_versions_and_inconsistent_offsets() {
    let mut tampered = MIXED_V2_0.to_vec();
    let len = tampered.len();
    // major/minor live at footer offsets 32..36.
    tampered[len - 8] = 9;
    assert!(validate_magic_footer(&tampered).is_err());

    let mut tampered = MIXED_V2_0.to_vec();
    // column_meta_start = the first footer u64: point it past the metadata.
    let bad = (len as u64).to_le_bytes();
    tampered[len - LANCE_FOOTER_LEN..len - LANCE_FOOTER_LEN + 8].copy_from_slice(&bad);
    assert!(validate_magic_footer(&tampered).is_err());
}

#[test]
fn conflicting_signals_and_partial_files_fail_closed() {
    // A file whose schema buffer was cut off is rejected, never partially
    // decoded.
    let mut truncated = MIXED_V2_0[..MIXED_V2_0.len() - LANCE_FOOTER_LEN].to_vec();
    truncated.extend_from_slice(&MIXED_V2_0[MIXED_V2_0.len() - LANCE_FOOTER_LEN..]);
    truncated.truncate(truncated.len() - LANCE_FOOTER_LEN + 4);
    assert!(decode_lance(truncated.as_slice(), LanceLimits::default(), |_| Ok(())).is_err());
}

// ---------------------------------------------------------------------------
// Level arithmetic
// ---------------------------------------------------------------------------

#[test]
fn definition_levels_round_trip_across_layer_shapes() {
    let cases = [
        (
            vec![RepDefLayer::NullableItem],
            vec![Termination::Item, Termination::NullItem],
        ),
        (
            vec![RepDefLayer::NullableItem, RepDefLayer::NullAndEmptyList],
            vec![
                Termination::Item,
                Termination::NullItem,
                Termination::NullList { list_layer: 1 },
                Termination::EmptyList { list_layer: 1 },
            ],
        ),
        (
            vec![RepDefLayer::AllValidItem, RepDefLayer::EmptyableList],
            vec![Termination::Item, Termination::EmptyList { list_layer: 1 }],
        ),
        (
            vec![RepDefLayer::AllValidItem, RepDefLayer::NullableItem],
            vec![Termination::Item, Termination::NullStruct { layer: 2 }],
        ),
    ];
    for (layers, terminations) in cases {
        for termination in terminations {
            let def = compute_def(&layers, termination).unwrap();
            assert_eq!(
                interpret_def(&layers, def).unwrap(),
                termination,
                "layers {layers:?}"
            );
        }
    }
}

#[test]
fn definition_levels_reject_values_beyond_the_layers() {
    assert!(interpret_def(&[RepDefLayer::AllValidItem], 1).is_err());
    assert!(
        compute_def(
            &[RepDefLayer::AllValidItem],
            Termination::NullList { list_layer: 1 }
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// Round-trips over the normalized IR
// ---------------------------------------------------------------------------

#[test]
fn primitive_and_nullable_columns_round_trip() {
    let schema = SchemaIr::new(SchemaNode::required(SchemaKind::Record {
        fields: vec![
            SchemaField {
                name: "flag".to_string(),
                schema: SchemaNode::required(SchemaKind::Boolean),
            },
            SchemaField {
                name: "count".to_string(),
                schema: SchemaNode::nullable(SchemaKind::I64),
            },
            SchemaField {
                name: "ratio".to_string(),
                schema: SchemaNode::required(SchemaKind::F64),
            },
            SchemaField {
                name: "name".to_string(),
                schema: SchemaNode::nullable(SchemaKind::String),
            },
            SchemaField {
                name: "blob".to_string(),
                schema: SchemaNode::required(SchemaKind::Bytes),
            },
        ],
    }));
    let values = vec![
        ir_record(vec![
            ("flag", Value::Boolean { value: true }),
            ("count", Value::I64 { value: 7 }),
            ("ratio", Value::F64 { value: 1.5 }),
            (
                "name",
                Value::String {
                    value: "ada@example.com".to_string(),
                },
            ),
            ("blob", Value::Bytes { value: vec![1, 2] }),
        ]),
        ir_record(vec![
            ("flag", Value::Boolean { value: false }),
            ("count", Value::Null),
            ("ratio", Value::F64 { value: -2.25 }),
            ("name", Value::Null),
            ("blob", Value::Bytes { value: vec![] }),
        ]),
    ];
    let (decoded_schema, decoded) = round_trip(&schema, &values);
    assert_eq!(decoded_schema, schema);
    assert_eq!(decoded, values);
}

#[test]
fn logical_types_round_trip() {
    let schema = SchemaIr::new(SchemaNode::required(SchemaKind::Record {
        fields: vec![
            SchemaField {
                name: "day".to_string(),
                schema: SchemaNode::required(SchemaKind::Date),
            },
            SchemaField {
                name: "at".to_string(),
                schema: SchemaNode::nullable(SchemaKind::Timestamp),
            },
            SchemaField {
                name: "amt".to_string(),
                schema: SchemaNode::required(SchemaKind::Decimal {
                    precision: 10,
                    scale: 2,
                }),
            },
            SchemaField {
                name: "clock".to_string(),
                schema: SchemaNode::required(SchemaKind::Time),
            },
        ],
    }));
    let values = vec![
        ir_record(vec![
            (
                "day",
                Value::Date {
                    value: "2022-01-08".to_string(),
                },
            ),
            (
                "at",
                Value::Timestamp {
                    value: "1970-01-01T00:20:34.56789Z".to_string(),
                },
            ),
            (
                "amt",
                Value::Decimal {
                    value: "1234500.00".to_string(),
                },
            ),
            (
                "clock",
                Value::Time {
                    value: "12:34:56.789".to_string(),
                },
            ),
        ]),
        ir_record(vec![
            (
                "day",
                Value::Date {
                    value: "2022-01-09".to_string(),
                },
            ),
            ("at", Value::Null),
            (
                "amt",
                Value::Decimal {
                    value: "-67.00".to_string(),
                },
            ),
            (
                "clock",
                Value::Time {
                    value: "00:00:00".to_string(),
                },
            ),
        ]),
    ];
    let (decoded_schema, decoded) = round_trip(&schema, &values);
    assert_eq!(decoded_schema, schema);
    assert_eq!(decoded, values);
}

#[test]
fn lists_and_nested_lists_round_trip() {
    let schema = SchemaIr::new(SchemaNode::required(SchemaKind::Record {
        fields: vec![
            SchemaField {
                name: "tags".to_string(),
                schema: SchemaNode::nullable(SchemaKind::Array {
                    items: Box::new(SchemaNode::nullable(SchemaKind::String)),
                }),
            },
            SchemaField {
                name: "nested".to_string(),
                schema: SchemaNode::nullable(SchemaKind::Array {
                    items: Box::new(SchemaNode::nullable(SchemaKind::Array {
                        items: Box::new(SchemaNode::required(SchemaKind::I64)),
                    })),
                }),
            },
        ],
    }));
    let values = vec![
        ir_record(vec![
            (
                "tags",
                Value::Array {
                    items: vec![
                        Value::String {
                            value: "a".to_string(),
                        },
                        Value::Null,
                        Value::String {
                            value: "b".to_string(),
                        },
                    ],
                },
            ),
            (
                "nested",
                Value::Array {
                    items: vec![
                        Value::Array {
                            items: vec![Value::I64 { value: 1 }, Value::I64 { value: 2 }],
                        },
                        Value::Array { items: vec![] },
                    ],
                },
            ),
        ]),
        ir_record(vec![
            ("tags", Value::Array { items: vec![] }),
            (
                "nested",
                Value::Array {
                    items: vec![
                        Value::Null,
                        Value::Array {
                            items: vec![Value::I64 { value: 3 }],
                        },
                    ],
                },
            ),
        ]),
        ir_record(vec![("tags", Value::Null), ("nested", Value::Null)]),
    ];
    let (decoded_schema, decoded) = round_trip(&schema, &values);
    assert_eq!(decoded_schema, schema);
    assert_eq!(decoded, values);
}

#[test]
fn structs_including_nullable_envelope_shaped_records_round_trip() {
    let envelope = SchemaNode::nullable(SchemaKind::Record {
        fields: ["alg", "iv", "enc_dek", "ct", "tag"]
            .into_iter()
            .map(|name| SchemaField {
                name: name.to_string(),
                schema: SchemaNode::required(SchemaKind::String),
            })
            .collect(),
    });
    let schema = SchemaIr::new(SchemaNode::required(SchemaKind::Record {
        fields: vec![
            SchemaField {
                name: "email".to_string(),
                schema: envelope.clone(),
            },
            SchemaField {
                name: "thing".to_string(),
                schema: SchemaNode::required(SchemaKind::Record {
                    fields: vec![SchemaField {
                        name: "a".to_string(),
                        schema: SchemaNode::required(SchemaKind::I64),
                    }],
                }),
            },
        ],
    }));
    let envelope_value = |tag: &str| Value::Record {
        fields: ["alg", "iv", "enc_dek", "ct", "tag"]
            .into_iter()
            .zip(["A", "B", "C", "D", tag])
            .map(|(name, value)| ValueField {
                name: name.to_string(),
                value: Value::String {
                    value: value.to_string(),
                },
            })
            .collect(),
    };
    let values = vec![
        ir_record(vec![
            ("email", envelope_value("t1")),
            (
                "thing",
                Value::Record {
                    fields: vec![ValueField {
                        name: "a".to_string(),
                        value: Value::I64 { value: 1 },
                    }],
                },
            ),
        ]),
        ir_record(vec![
            ("email", Value::Null),
            (
                "thing",
                Value::Record {
                    fields: vec![ValueField {
                        name: "a".to_string(),
                        value: Value::I64 { value: 2 },
                    }],
                },
            ),
        ]),
    ];
    let (decoded_schema, decoded) = round_trip(&schema, &values);
    assert_eq!(decoded_schema, schema);
    assert_eq!(decoded, values);
}

#[test]
fn lists_of_structs_round_trip() {
    let schema = SchemaIr::new(SchemaNode::required(SchemaKind::Record {
        fields: vec![SchemaField {
            name: "rows".to_string(),
            schema: SchemaNode::nullable(SchemaKind::Array {
                items: Box::new(SchemaNode::nullable(SchemaKind::Record {
                    fields: vec![
                        SchemaField {
                            name: "a".to_string(),
                            schema: SchemaNode::required(SchemaKind::I64),
                        },
                        SchemaField {
                            name: "b".to_string(),
                            schema: SchemaNode::nullable(SchemaKind::String),
                        },
                    ],
                })),
            }),
        }],
    }));
    let row = |a: i64, b: Option<&str>| Value::Record {
        fields: vec![
            ValueField {
                name: "a".to_string(),
                value: Value::I64 { value: a },
            },
            ValueField {
                name: "b".to_string(),
                value: match b {
                    Some(b) => Value::String {
                        value: b.to_string(),
                    },
                    None => Value::Null,
                },
            },
        ],
    };
    let values = vec![
        ir_record(vec![(
            "rows",
            Value::Array {
                items: vec![row(1, Some("x")), Value::Null, row(2, None)],
            },
        )]),
        ir_record(vec![("rows", Value::Array { items: vec![] })]),
        ir_record(vec![("rows", Value::Null)]),
    ];
    let (decoded_schema, decoded) = round_trip(&schema, &values);
    assert_eq!(decoded_schema, schema);
    assert_eq!(decoded, values);
}

#[test]
fn maps_are_rejected_for_lance_output() {
    let schema = SchemaIr::new(SchemaNode::required(SchemaKind::Record {
        fields: vec![SchemaField {
            name: "m".to_string(),
            schema: SchemaNode::required(SchemaKind::Map {
                values: Box::new(SchemaNode::required(SchemaKind::I64)),
            }),
        }],
    }));
    let values = vec![ir_record(vec![(
        "m",
        Value::Map {
            entries: vec![MapEntry {
                key: "k".to_string(),
                value: Value::I64 { value: 1 },
            }],
        },
    )])];
    let error = encode_lance(&schema, &values, LanceLimits::default()).unwrap_err();
    assert_eq!(error.code(), codes::UNSUPPORTED_FORMAT);
}

// ---------------------------------------------------------------------------
// Reference-implementation interoperability
// ---------------------------------------------------------------------------

#[test]
fn pylance_written_v2_0_file_decodes_to_the_expected_values() {
    let (schema, values) = decode_all(MIXED_V2_0);
    let SchemaKind::Record { fields } = &schema.root.kind else {
        panic!("expected a record schema");
    };
    let names: Vec<&str> = fields.iter().map(|field| field.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "id", "email", "score", "tags", "note", "flag", "day", "ts", "amt", "vec", "nested",
            "thing"
        ]
    );
    assert_eq!(values.len(), 2);
    let Value::Record { fields } = &values[0].root else {
        panic!("expected a record value");
    };
    assert_eq!(fields[0].value, Value::I64 { value: 7 });
    assert_eq!(
        fields[1].value,
        Value::String {
            value: "ada@example.com".to_string()
        }
    );
    assert_eq!(fields[2].value, Value::F64 { value: 1.5 });
    assert_eq!(
        fields[3].value,
        Value::Array {
            items: vec![
                Value::String {
                    value: "a".to_string()
                },
                Value::String {
                    value: "b".to_string()
                },
            ]
        }
    );
    assert_eq!(fields[4].value, Value::Bytes { value: vec![1, 2] });
    assert_eq!(fields[5].value, Value::Boolean { value: true });
    assert_eq!(
        fields[6].value,
        Value::Date {
            value: "2022-01-08".to_string()
        }
    );
    assert_eq!(
        fields[7].value,
        Value::Timestamp {
            value: "1970-01-01T00:20:34.56789Z".to_string()
        }
    );
    assert_eq!(
        fields[8].value,
        Value::Decimal {
            value: "1234500.00".to_string()
        }
    );
    assert_eq!(
        fields[9].value,
        Value::Array {
            items: vec![Value::F64 { value: 1.0 }, Value::F64 { value: 2.0 }]
        }
    );
    assert_eq!(
        fields[10].value,
        Value::Array {
            items: vec![
                Value::Array {
                    items: vec![Value::I64 { value: 1 }, Value::I64 { value: 2 }]
                },
                Value::Array { items: vec![] },
            ]
        }
    );
    let Value::Record { fields: thing } = &fields[11].value else {
        panic!("expected a struct value");
    };
    assert_eq!(thing[0].value, Value::I64 { value: 1 });
    assert_eq!(
        thing[1].value,
        Value::String {
            value: "s".to_string()
        }
    );

    let Value::Record { fields } = &values[1].root else {
        panic!("expected a record value");
    };
    assert_eq!(fields[1].value, Value::Null);
    assert_eq!(fields[5].value, Value::Null);
    assert_eq!(fields[7].value, Value::Null);
    assert_eq!(
        fields[8].value,
        Value::Decimal {
            value: "-6700.00".to_string()
        }
    );
    let Value::Record { fields: thing } = &fields[11].value else {
        panic!("expected a struct value");
    };
    assert_eq!(thing[1].value, Value::Null);
}

#[test]
fn pylance_written_v2_2_structural_file_decodes() {
    let (schema, values) = decode_all(INT_V2_2);
    let SchemaKind::Record { fields } = &schema.root.kind else {
        panic!("expected a record schema");
    };
    assert_eq!(fields[0].name, "x");
    assert_eq!(values.len(), 2);
    let Value::Record { fields } = &values[0].root else {
        panic!("expected a record value");
    };
    assert_eq!(fields[0].value, Value::I64 { value: 7 });
    let Value::Record { fields } = &values[1].root else {
        panic!("expected a record value");
    };
    assert_eq!(fields[0].value, Value::I64 { value: 8 });
}

#[test]
fn unsupported_page_encodings_fail_closed() {
    // The 2.2 fixture uses flat mini-block pages this codec reads; a file
    // declaring an unknown page encoding must be rejected, not guessed at.
    let mut tampered = INT_V2_2.to_vec();
    // Flip the page-layout type URL bytes inside the metadata region.
    let needle = b"/lance.encodings21.PageLayout";
    let position = tampered
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("fixture contains the page layout type URL");
    tampered[position + 8] = b'X';
    assert!(decode_lance(tampered.as_slice(), LanceLimits::default(), |_| Ok(())).is_err());
}

// ---------------------------------------------------------------------------
// Limits and validation
// ---------------------------------------------------------------------------

#[test]
fn source_limit_fails_before_lance_bytes_are_unbounded() {
    let error = decode_lance(
        MIXED_V2_0,
        LanceLimits {
            max_source_bytes: 4,
            ..LanceLimits::default()
        },
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.code(), codes::UNSUPPORTED_FORMAT);
}

#[test]
fn zero_source_limit_is_a_configuration_error() {
    let error = decode_lance(
        MIXED_V2_0,
        LanceLimits {
            max_source_bytes: 0,
            ..LanceLimits::default()
        },
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.code(), codes::CONFIG_INVALID);
}

#[test]
fn values_that_violate_their_schema_are_rejected_before_encoding() {
    let schema = string_schema();
    let values = vec![ir_record(vec![("x", Value::I64 { value: 1 })])];
    assert!(encode_lance(&schema, &values, LanceLimits::default()).is_err());
}

// ---------------------------------------------------------------------------
// The typed pump
// ---------------------------------------------------------------------------

struct Uppercase;

impl BinaryTransform for Uppercase {
    fn output_schema(&mut self, input_schema: &SchemaIr) -> Result<SchemaIr, MaskuraError> {
        Ok(input_schema.clone())
    }

    fn transform(
        &mut self,
        value: ValueIr,
        _input_schema: &SchemaIr,
        _output_schema: &SchemaIr,
    ) -> Result<Option<ValueIr>, MaskuraError> {
        let Value::Record { mut fields } = value.root else {
            return Err(MaskuraError::new(codes::INTERNAL, "test expects a record"));
        };
        match &mut fields[1].value {
            Value::String { value } => *value = value.to_uppercase(),
            Value::Null => {}
            _ => {
                return Err(MaskuraError::new(
                    codes::INTERNAL,
                    "test expects a string field",
                ));
            }
        }
        Ok(Some(ValueIr::new(Value::Record { fields })))
    }
}

#[test]
fn process_lance_routes_each_record_through_the_typed_pump() {
    let mut pump = crate::binary_pump::BinaryPump::new(
        CommonTypeBinaryReductor::default(),
        Uppercase,
        BinaryIrLimits::default(),
    );
    let output = process_lance(MIXED_V2_0, LanceLimits::default(), &mut pump).unwrap();
    let (_schema, values) = decode_all(&output);
    let Value::Record { fields } = &values[0].root else {
        panic!("expected a record");
    };
    assert_eq!(
        fields[1].value,
        Value::String {
            value: "ADA@EXAMPLE.COM".to_string(),
        }
    );
}

#[test]
fn process_lance_emits_the_typed_envelope_schema() {
    let (public, _private) = generate_keypair([0x11; 32], [0x22; 64]);
    let public_pem = public.to_pem();
    let target = crate::binary_ir::SchemaPath(vec![crate::binary_ir::SchemaPathSegment::Field(
        "email".to_string(),
    )]);
    let mut pump = crate::binary_pump::BinaryPump::new(
        CommonTypeBinaryReductor::default(),
        EnvelopeBinaryTransform::new(vec![target], Some(&public_pem)).unwrap(),
        BinaryIrLimits::default(),
    );
    let output = process_lance(MIXED_V2_0, LanceLimits::default(), &mut pump).unwrap();
    assert!(
        !output
            .windows(b"ada@example.com".len())
            .any(|window| window == b"ada@example.com")
    );
    let (schema, values) = decode_all(&output);
    let SchemaKind::Record { fields } = &schema.root.kind else {
        panic!("expected a record schema");
    };
    assert!(matches!(fields[1].schema.kind, SchemaKind::Record { .. }));
    let Value::Record { fields } = &values[0].root else {
        panic!("expected a record value");
    };
    assert!(matches!(fields[1].value, Value::Record { .. }));
    let Value::Record { fields } = &values[1].root else {
        panic!("expected a record value");
    };
    assert_eq!(fields[1].value, Value::Null);
}

#[test]
fn process_lance_can_drop_records() {
    struct DropSecond;

    impl BinaryTransform for DropSecond {
        fn output_schema(&mut self, input_schema: &SchemaIr) -> Result<SchemaIr, MaskuraError> {
            Ok(input_schema.clone())
        }

        fn transform(
            &mut self,
            value: ValueIr,
            _input_schema: &SchemaIr,
            _output_schema: &SchemaIr,
        ) -> Result<Option<ValueIr>, MaskuraError> {
            let Value::Record { fields } = &value.root else {
                return Err(MaskuraError::new(codes::INTERNAL, "test expects a record"));
            };
            Ok((fields[0].value != Value::I64 { value: 8 }).then_some(value))
        }
    }

    let mut pump = crate::binary_pump::BinaryPump::new(
        CommonTypeBinaryReductor::default(),
        DropSecond,
        BinaryIrLimits::default(),
    );
    let output = process_lance(MIXED_V2_0, LanceLimits::default(), &mut pump).unwrap();
    let (_schema, values) = decode_all(&output);
    assert_eq!(values.len(), 1);
}
