# Markdown Paste-Merge

Status: Developed

## Objectives

- Add a Markdown editor toolbar action that reads text from the clipboard and appends it to the current Markdown document.
- Merge pasted reference-style numbered links without conflicts by renumbering pasted references after the existing document references.
- Keep a single numbered reference definition block at the end of the Markdown document when the existing document already has one.
- Place the editor cursor at the end of the newly pasted body text, before the final reference definition block when such a block exists.

## Technical Details

### UI Contract

- The Markdown editor toolbar includes a `Paste-Merge` `CompactButton` next to the existing editor actions.
- The button is disabled when the opened content is not Markdown.
- Clicking the button reads clipboard text through a browser service helper.
- Clipboard content is accepted when it is text and has non-whitespace content. No full Markdown validation is required.
- Empty text or clipboard read failure shows an error notification and leaves the editor unchanged.
- A successful merge updates `contentValue`, marks the editor dirty through the existing snapshot flow, focuses Ace, and moves the cursor to the end of the newly pasted body text.
- If the merged document has a final numbered reference definition block, the cursor target is before that block. If there is no final reference block, the cursor target is the end of the document.

### Integration Points

- `nop/ts/admin/src/routes/ContentEditorView.svelte`
  - Owns `contentValue`, `isMarkdown`, `editorRef`, notifications, and editor toolbar rendering.
  - Calls the paste-merge helper and assigns the returned Markdown to `contentValue`.
  - Moves the Ace cursor using the helper's returned insertion cursor offset.
- `nop/ts/admin/src/services/browser.ts`
  - Exposes `readClipboardText(): Promise<string | null>`.
  - Uses `navigator.clipboard.readText()` when available and returns `null` on unsupported APIs or permission failures.
- `nop/ts/admin/src/services/markdownPasteMerge.ts`
  - Contains the pure parser/merge logic and focused Vitest tests.

### Merge Helper Contract

The helper exposes a result that includes the merged Markdown and the cursor position:

```ts
export type PasteMergeResult = {
  content: string;
  cursorOffset: number;
  existingReferenceCount: number;
  pastedReferenceCount: number;
};

export function pasteMergeMarkdown(existing: string, pasted: string): PasteMergeResult;
```

`cursorOffset` is a zero-based string offset into `content`. The UI converts it to an Ace position with `editorRef.session.getDocument().indexToPosition(cursorOffset, 0)` and then calls `moveCursorToPosition`.

### Reference Definition Parsing

- Numbered reference definitions use this supported shape:

```md
[1]: https://example.com "Optional title"
```

- Definition detection accepts up to three leading spaces:

```ts
/^[ \t]{0,3}\[(\d+)\]:[ \t]*(.*)$/
```

- Parsing must ignore fenced code blocks opened by backtick or tilde fences.
- The merge process supports single-line reference definitions.
- Multi-line reference definitions may remain in the body and are not part of the compact Paste-Merge contract.

### Body And Reference Block Splitting

Each document is split into:

- `body`: Markdown without the trailing numbered reference definition block.
- `trailingDefinitions`: the final contiguous numbered reference definitions.
- `allReferenceNumbers`: numbered reference definitions and numbered in-text reference labels found outside fenced code blocks.

The final reference block is identified from the bottom of the document by walking upward across blank lines and numbered definition lines. Non-definition content stops the scan.

The existing document's trailing definitions are moved to the new end. The pasted document's trailing definitions are renumbered and appended after existing trailing definitions.

### Renumbering Rules

- Determine `nextReferenceNumber` as `max(existing numbered definition labels and in-text reference labels outside fenced code blocks) + 1`.
- Build a mapping for every numbered label used by the pasted body and for every numbered label defined in the pasted trailing reference block.
- Pasted labels are assigned in first-seen numeric order of their original label, starting at `nextReferenceNumber`.
- Pasted in-text references are rewritten using that mapping.
- Pasted trailing definition labels are rewritten using that mapping.
- Existing body text and existing reference definitions are not renumbered.
- Orphaned pasted in-text references are renumbered even when the pasted text has no matching reference definition. No definition is created for the orphan. This preserves the pasted document's missing-definition state without allowing it to point at an existing document reference.

For example, if the existing document already has `[1]` through `[4]`, and pasted text contains `][1]`, `][2]`, and `][9]` but only defines `[1]` and `[2]`, the pasted body is rewritten to `][5]`, `][6]`, and `][7]`; only definitions `[5]` and `[6]` are appended.

### In-Text Reference Rewriting

Only the reference-label half of reference-style links should be rewritten:

```md
[visible text][1]
![image alt][2]
```

Use a pattern equivalent to:

```ts
/(\]\[)(\d+)(\])/g
```

Rewriting should ignore fenced code blocks. Plain standalone `[1]` text should not be rewritten unless it is the label part of a reference-style link.

### Output Composition

The helper composes the result in this order:

```md
<existing body>

<renumbered pasted body>

<existing trailing definitions>
<renumbered pasted trailing definitions>
```

Spacing is deterministic:

- Trim only trailing whitespace needed to avoid accidental blank-line growth.
- Preserve body content internally.
- Use two newlines between existing body and pasted body when both are non-empty.
- Use two newlines between the combined body and the final reference definition block when definitions exist.
- End the result with a single newline when the result is non-empty.

The `cursorOffset` points to the end of `<renumbered pasted body>` after output composition and before the blank lines that precede the final reference definition block.

### Test Fixtures

Tests generate local Markdown strings in the test file. They do not depend on repository fixture directories or external files.

Sequential merge coverage uses three compact documents:

Birds:

```md
## Bird Committee Notes

The sparrow filed a tiny incident report about crumbs ([Feather Court][1]).
An owl objected from the chandelier and cited moonlight precedent ([Night Desk][2]).

[1]: https://example.test/birds/crumbs "Crumb Hearing"
[2]: https://example.test/birds/moonlight "Moonlight Precedent"
```

Cats:

```md
## Cat Operations

Marmalade the cat approved the keyboard nap policy ([Purr Manual][1]).
The kitten referenced an invisible laser pointer memo ([Laser Memo][3]).

[1]: https://example.test/cats/purr-manual "Purr Manual"
```

Dogs:

```md
## Dog Logistics

The dog team scheduled a bark audit after lunch ([Bark Ledger][1]).
One terrier mentioned a missing sock appendix ([Sock Appendix][2]).

[1]: https://example.test/dogs/bark-ledger "Bark Ledger"
[2]: https://example.test/dogs/sock-appendix "Sock Appendix"
```

The sequential test merges Birds, then Cats, then Dogs. The Cat document intentionally contains an orphaned `[3]` in-text reference. After merging Cats into Birds, Cat references become `[3]` and `[4]`, but only `[3]` has a definition. After merging Dogs, Dog references continue after the highest existing or allocated pasted reference number, so Dog references become `[5]` and `[6]`.

### Test Coverage

- Sequential merge with the Birds, Cats, and Dogs documents above.
- Existing document with no trailing reference block.
- Pasted text with no reference definitions.
- Pasted orphaned in-text reference labels are renumbered without generating definitions.
- Existing reference numbering with gaps uses the maximum existing number, not the count.
- Reference definitions and in-text labels inside fenced code blocks are ignored.
- Cursor offset points after the pasted body and before the final reference block.
- `ContentEditorView` updates `contentValue` and moves Ace to the helper's `cursorOffset`.

### Security And Browser Notes

- Clipboard reads must happen from the button click handler so browser permission checks see a user gesture.
- Clipboard text is treated as untrusted user input and is only inserted into the editor buffer. It is saved through the existing Markdown save path and backend validation.
- The feature does not add backend APIs, management bus operations, or direct filesystem access.

<!--
This file is part of the product NoPressure.
SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
SPDX-License-Identifier: AGPL-3.0-or-later
The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.
-->
