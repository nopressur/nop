// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

pub const WS_MAX_MESSAGE_BYTES: usize = 63 * 1024;
// Response frame overhead: frame_type + domain_id + action_id + workflow_id + payload_len.
pub const WS_RESPONSE_FRAME_OVERHEAD_BYTES: usize = 20;
pub const WS_MAX_RESPONSE_PAYLOAD_BYTES: usize =
    WS_MAX_MESSAGE_BYTES - WS_RESPONSE_FRAME_OVERHEAD_BYTES;
// StreamChunk frame overhead: frame_type + stream_id + seq + flags + payload_len.
pub const WS_STREAM_CHUNK_OVERHEAD_BYTES: usize = 17;
pub const WS_MAX_STREAM_CHUNK_BYTES: usize = WS_MAX_MESSAGE_BYTES - WS_STREAM_CHUNK_OVERHEAD_BYTES;
