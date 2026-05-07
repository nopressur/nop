// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use crate::content::ContentSummary;
use crate::wire::{OptionMap, WireDecode, WireEncode, WireReader, WireResult, WireWriter};
use serde::{Deserialize, Serialize};

pub const SEARCH_DOMAIN_ID: u32 = 21;

pub const SEARCH_ACTION_FIND: u32 = 1;
pub const SEARCH_ACTION_INVALIDATE: u32 = 2;
pub const SEARCH_ACTION_RESET: u32 = 3;

pub const SEARCH_ACTION_FIND_OK: u32 = 101;
pub const SEARCH_ACTION_FIND_ERR: u32 = 102;
pub const SEARCH_ACTION_INVALIDATE_OK: u32 = 201;
pub const SEARCH_ACTION_INVALIDATE_ERR: u32 = 202;
pub const SEARCH_ACTION_RESET_OK: u32 = 301;
pub const SEARCH_ACTION_RESET_ERR: u32 = 302;

#[derive(Debug, Clone)]
pub enum SearchCommand {
    Find(SearchFindRequest),
    Invalidate(SearchInvalidateRequest),
    Reset(SearchResetRequest),
}

impl SearchCommand {
    pub fn action_id(&self) -> u32 {
        match self {
            SearchCommand::Find(_) => SEARCH_ACTION_FIND,
            SearchCommand::Invalidate(_) => SEARCH_ACTION_INVALIDATE,
            SearchCommand::Reset(_) => SEARCH_ACTION_RESET,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchFindRequest {
    pub query: String,
    pub tags: Option<Vec<String>>,
    pub markdown_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchFindResponse {
    pub hits: Vec<ContentSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchInvalidateRequest {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResetRequest {}

impl WireEncode for SearchFindRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        let option_flags = [self.tags.is_some()];
        OptionMap::from_flags(&option_flags)?.write(writer)?;
        writer.write_string(&self.query)?;
        writer.write_bool(self.markdown_only);
        if let Some(tags) = &self.tags {
            writer.write_vec(tags, |writer, tag| writer.write_string(tag))?;
        }
        Ok(())
    }
}

impl WireDecode for SearchFindRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let flags = OptionMap::read(reader, 1)?;
        let query = reader.read_string()?;
        let markdown_only = reader.read_bool()?;
        let tags = if flags[0] {
            Some(reader.read_vec(|reader| reader.read_string())?)
        } else {
            None
        };
        Ok(Self {
            query,
            tags,
            markdown_only,
        })
    }
}

impl WireEncode for SearchFindResponse {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_vec(&self.hits, |writer, item| item.encode(writer))
    }
}

impl WireDecode for SearchFindResponse {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let hits = reader.read_vec(ContentSummary::decode)?;
        Ok(Self { hits })
    }
}

impl WireEncode for SearchInvalidateRequest {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()> {
        writer.write_string(&self.id)?;
        Ok(())
    }
}

impl WireDecode for SearchInvalidateRequest {
    fn decode(reader: &mut WireReader) -> WireResult<Self> {
        let id = reader.read_string()?;
        Ok(Self { id })
    }
}

impl WireEncode for SearchResetRequest {
    fn encode(&self, _writer: &mut WireWriter) -> WireResult<()> {
        Ok(())
    }
}

impl WireDecode for SearchResetRequest {
    fn decode(_reader: &mut WireReader) -> WireResult<Self> {
        Ok(Self {})
    }
}
