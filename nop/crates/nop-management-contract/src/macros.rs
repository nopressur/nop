// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

#[macro_export]
macro_rules! define_domain_responses {
    ($domain_id:expr) => {
        fn response_ok(
            action_id: u32,
            workflow_id: u32,
            message: &str,
        ) -> $crate::core::ManagementResponse {
            $crate::core::ManagementResponse::message($domain_id, action_id, workflow_id, message)
                .unwrap_or_else(|_| $crate::core::ManagementResponse {
                    domain_id: $domain_id,
                    action_id,
                    workflow_id,
                    payload: $crate::core::ResponsePayload::Message(
                        $crate::core::MessageResponse {
                            message: message.to_string(),
                        },
                    ),
                })
        }

        fn response_err(
            action_id: u32,
            workflow_id: u32,
            message: &str,
        ) -> $crate::core::ManagementResponse {
            $crate::core::ManagementResponse::message($domain_id, action_id, workflow_id, message)
                .unwrap_or_else(|_| $crate::core::ManagementResponse {
                    domain_id: $domain_id,
                    action_id,
                    workflow_id,
                    payload: $crate::core::ResponsePayload::Message(
                        $crate::core::MessageResponse {
                            message: message.to_string(),
                        },
                    ),
                })
        }
    };
    ($domain_id:expr, ok_fallback = $ok_fallback:expr, err_fallback = $err_fallback:expr) => {
        fn response_ok(
            action_id: u32,
            workflow_id: u32,
            message: &str,
        ) -> $crate::core::ManagementResponse {
            $crate::core::ManagementResponse::message($domain_id, action_id, workflow_id, message)
                .unwrap_or_else(|_| $crate::core::ManagementResponse {
                    domain_id: $domain_id,
                    action_id,
                    workflow_id,
                    payload: $crate::core::ResponsePayload::Message(
                        $crate::core::MessageResponse {
                            message: $ok_fallback.to_string(),
                        },
                    ),
                })
        }

        fn response_err(
            action_id: u32,
            workflow_id: u32,
            message: &str,
        ) -> $crate::core::ManagementResponse {
            $crate::core::ManagementResponse::message($domain_id, action_id, workflow_id, message)
                .unwrap_or_else(|_| $crate::core::ManagementResponse {
                    domain_id: $domain_id,
                    action_id,
                    workflow_id,
                    payload: $crate::core::ResponsePayload::Message(
                        $crate::core::MessageResponse {
                            message: $err_fallback.to_string(),
                        },
                    ),
                })
        }
    };
}

#[macro_export]
macro_rules! define_request_codec {
    (
        $codec:ident,
        domain = $domain_enum:ident,
        command = $command_enum:ident,
        variant = $variant:ident,
        domain_id = $domain_id:expr,
        action_id = $action_id:expr,
        request = $request_ty:ty,
        validate = |$validate_request:ident| $validate:expr,
        limits = $limits:expr,
        values = |$values_request:ident| $values:expr,
        error = $error:literal $(,)?
    ) => {
        pub struct $codec;

        impl $crate::codec::RequestCodec for $codec {
            fn key(&self) -> $crate::registry::DomainActionKey {
                $crate::registry::DomainActionKey::new($domain_id, $action_id)
            }

            fn limits(&self) -> $crate::codec::FieldLimits {
                $limits
            }

            fn decode(
                &self,
                payload: &[u8],
            ) -> Result<$crate::core::ManagementCommand, $crate::codec::CodecError> {
                let request: $request_ty = $crate::codec::decode_payload(payload)?;
                Ok($crate::core::ManagementCommand::$domain_enum(
                    $command_enum::$variant(request),
                ))
            }

            fn encode(
                &self,
                command: &$crate::core::ManagementCommand,
            ) -> Result<Vec<u8>, $crate::codec::CodecError> {
                match command {
                    $crate::core::ManagementCommand::$domain_enum($command_enum::$variant(
                        request,
                    )) => $crate::codec::encode_payload(request),
                    _ => Err($crate::codec::CodecError::new(
                        $crate::errors::ManagementErrorKind::Codec,
                        $error,
                    )),
                }
            }

            fn validate(
                &self,
                command: &$crate::core::ManagementCommand,
            ) -> Result<(), $crate::codec::CodecError> {
                match command {
                    $crate::core::ManagementCommand::$domain_enum($command_enum::$variant(
                        $validate_request,
                    )) => {
                        $validate.map_err(|err| {
                            $crate::codec::CodecError::new(
                                $crate::errors::ManagementErrorKind::Validation,
                                err.to_string(),
                            )
                        })?;
                        let $values_request = $validate_request;
                        let values = $values;
                        $crate::codec::validate_field_limits(&self.limits(), &values)
                    }
                    _ => Err($crate::codec::CodecError::new(
                        $crate::errors::ManagementErrorKind::Codec,
                        $error,
                    )),
                }
            }
        }
    };
}

#[macro_export]
macro_rules! define_response_codec {
    (
        $codec:ident,
        domain_id = $domain_id:expr,
        action_id = $action_id:expr,
        payload = $payload_variant:ident,
        response = $response_ty:ty,
        limits = $limits:expr,
        values = |$payload:ident| $values:expr,
        error = $error:literal $(,)?
    ) => {
        pub struct $codec;

        impl $crate::codec::ResponseCodec for $codec {
            fn key(&self) -> $crate::registry::DomainActionKey {
                $crate::registry::DomainActionKey::new($domain_id, $action_id)
            }

            fn limits(&self) -> $crate::codec::FieldLimits {
                $limits
            }

            fn encode(
                &self,
                response: &$crate::core::ManagementResponse,
            ) -> Result<Vec<u8>, $crate::codec::CodecError> {
                match &response.payload {
                    $crate::core::ResponsePayload::$payload_variant($payload) => {
                        $crate::codec::encode_payload($payload)
                    }
                    _ => Err($crate::codec::CodecError::new(
                        $crate::errors::ManagementErrorKind::Codec,
                        $error,
                    )),
                }
            }

            fn decode(
                &self,
                payload: &[u8],
            ) -> Result<$crate::core::ResponsePayload, $crate::codec::CodecError> {
                let response: $response_ty = $crate::codec::decode_payload(payload)?;
                Ok($crate::core::ResponsePayload::$payload_variant(response))
            }

            fn validate(
                &self,
                response: &$crate::core::ManagementResponse,
            ) -> Result<(), $crate::codec::CodecError> {
                match &response.payload {
                    $crate::core::ResponsePayload::$payload_variant($payload) => {
                        let values = $values;
                        $crate::codec::validate_field_limits(&self.limits(), &values)
                    }
                    _ => Err($crate::codec::CodecError::new(
                        $crate::errors::ManagementErrorKind::Codec,
                        $error,
                    )),
                }
            }
        }
    };
}

#[macro_export]
macro_rules! define_message_response_codec {
    (
        $codec:ident,
        domain_id = $domain_id:expr,
        error = $error:literal $(,)?
    ) => {
        pub struct $codec {
            action_id: u32,
        }

        impl $codec {
            pub fn new(action_id: u32) -> Self {
                Self { action_id }
            }
        }

        impl $crate::codec::ResponseCodec for $codec {
            fn key(&self) -> $crate::registry::DomainActionKey {
                $crate::registry::DomainActionKey::new($domain_id, self.action_id)
            }

            fn limits(&self) -> $crate::codec::FieldLimits {
                $crate::codec::FieldLimits::new(vec![(
                    "message",
                    $crate::codec::FieldLimit::MaxChars(1024),
                )])
            }

            fn encode(
                &self,
                response: &$crate::core::ManagementResponse,
            ) -> Result<Vec<u8>, $crate::codec::CodecError> {
                match &response.payload {
                    $crate::core::ResponsePayload::Message(payload) => {
                        $crate::codec::encode_payload(payload)
                    }
                    _ => Err($crate::codec::CodecError::new(
                        $crate::errors::ManagementErrorKind::Codec,
                        $error,
                    )),
                }
            }

            fn decode(
                &self,
                payload: &[u8],
            ) -> Result<$crate::core::ResponsePayload, $crate::codec::CodecError> {
                let response: $crate::core::MessageResponse =
                    $crate::codec::decode_payload(payload)?;
                let message =
                    $crate::core::MessageResponse::new(response.message).map_err(|err| {
                        $crate::codec::CodecError::new(
                            $crate::errors::ManagementErrorKind::Codec,
                            err.to_string(),
                        )
                    })?;
                Ok($crate::core::ResponsePayload::Message(message))
            }

            fn validate(
                &self,
                response: &$crate::core::ManagementResponse,
            ) -> Result<(), $crate::codec::CodecError> {
                match &response.payload {
                    $crate::core::ResponsePayload::Message(payload) => {
                        let mut values = $crate::codec::FieldValues::new();
                        values.insert_len("message", payload.message.chars().count());
                        $crate::codec::validate_field_limits(&self.limits(), &values)
                    }
                    _ => Err($crate::codec::CodecError::new(
                        $crate::errors::ManagementErrorKind::Codec,
                        $error,
                    )),
                }
            }
        }
    };
}

#[macro_export]
macro_rules! register_request_codecs {
    ($registry:expr, [$( $codec:expr ),+ $(,)?]) => {
        $(
            $registry.register_request_codec(std::sync::Arc::new($codec))?;
        )+
    };
}

#[macro_export]
macro_rules! register_response_codecs {
    ($registry:expr, [$( $codec:expr ),+ $(,)?]) => {
        $(
            $registry.register_response_codec(std::sync::Arc::new($codec))?;
        )+
    };
}
