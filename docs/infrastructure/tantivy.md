# Custom In-Memory Directory for Tantivy

This example demonstrates how to implement a custom `Directory` trait for Tantivy to use an in-memory storage backend instead of the default file system. Tantivy's `Directory` trait abstracts storage, allowing you to create custom implementations like this one for in-memory data.

## Example Code

### In-Memory Directory Implementation

```rust
use tantivy::directory::{Directory, WritePtr, FileHandle, OwnedBytes};
use tantivy::Result;
use std::collections::HashMap;
use std::io::{Write, Cursor};

// In-memory directory storing files as a HashMap of path to bytes
struct InMemoryDirectory {
    files: HashMap<String, Vec<u8>>,
}

impl Directory for InMemoryDirectory {
    fn get_file_handle(&self, path: &str) -> Result<Box<dyn FileHandle>> {
        let data = self.files.get(path).cloned().unwrap_or_default();
        Ok(Box::new(InMemoryFileHandle { data }))
    }

    fn open_write(&self, _path: &str) -> Result<WritePtr> {
        Ok(WritePtr::new(Box::new(Cursor::new(Vec::new()))))
    }

    // Minimal implementation for other required methods
    fn atomic_read(&self, path: &str) -> Result<Vec<u8>> {
        Ok(self.files.get(path).cloned().unwrap_or_default())
    }

    fn atomic_write(&self, path: &str, data: &[u8]) -> Result<()> {
        self.files.insert(path.to_string(), data.to_vec());
        Ok(())
    }

    fn delete(&self, _path: &str) -> Result<()> {
        Ok(())
    }

    fn exists(&self, path: &str) -> Result<bool> {
        Ok(self.files.contains_key(path))
    }
}

// File handle for in-memory data
struct InMemoryFileHandle {
    data: Vec<u8>,
}

impl FileHandle for InMemoryFileHandle {
    fn read_bytes(&self, range: std::ops::Range<u64>) -> Result<OwnedBytes> {
        let start = range.start as usize;
        let end = range.end as usize;
        Ok(OwnedBytes::new(self.data[start..end].to_vec()))
    }
}
```

### Using the In-Memory Directory

```rust
use tantivy::Index;
use tantivy::schema::{Schema, TEXT};
use tantivy::Result;

fn main() -> Result<()> {
    // Create a schema
    let mut schema_builder = Schema::builder();
    schema_builder.add_text_field("title", TEXT);
    let schema = schema_builder.build();

    // Initialize in-memory directory
    let in_memory_dir = Box::new(InMemoryDirectory {
        files: HashMap::new(),
    });

    // Create Tantivy index with custom directory
    let index = Index::create_from_directory(in_memory_dir, schema, None)?;

    // Now you can use the index as usual
    Ok(())
}
````

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
