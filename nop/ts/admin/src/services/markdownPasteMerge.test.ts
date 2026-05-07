// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

import { describe, expect, it } from "vitest";
import { pasteMergeMarkdown } from "./markdownPasteMerge";

const birds = `## Bird Committee Notes

The sparrow filed a tiny incident report about crumbs ([Feather Court][1]).
An owl objected from the chandelier and cited moonlight precedent ([Night Desk][2]).

[1]: https://example.test/birds/crumbs "Crumb Hearing"
[2]: https://example.test/birds/moonlight "Moonlight Precedent"
`;

const cats = `## Cat Operations

Marmalade the cat approved the keyboard nap policy ([Purr Manual][1]).
The kitten referenced an invisible laser pointer memo ([Laser Memo][3]).

[1]: https://example.test/cats/purr-manual "Purr Manual"
`;

const dogs = `## Dog Logistics

The dog team scheduled a bark audit after lunch ([Bark Ledger][1]).
One terrier mentioned a missing sock appendix ([Sock Appendix][2]).

[1]: https://example.test/dogs/bark-ledger "Bark Ledger"
[2]: https://example.test/dogs/sock-appendix "Sock Appendix"
`;

describe("pasteMergeMarkdown", () => {
  it("merges sequential generated markdown texts and renumbers orphaned labels", () => {
    const birdsResult = pasteMergeMarkdown("", birds);
    const catsResult = pasteMergeMarkdown(birdsResult.content, cats);
    const dogsResult = pasteMergeMarkdown(catsResult.content, dogs);

    expect(dogsResult.content).toBe(`## Bird Committee Notes

The sparrow filed a tiny incident report about crumbs ([Feather Court][1]).
An owl objected from the chandelier and cited moonlight precedent ([Night Desk][2]).

## Cat Operations

Marmalade the cat approved the keyboard nap policy ([Purr Manual][3]).
The kitten referenced an invisible laser pointer memo ([Laser Memo][4]).

## Dog Logistics

The dog team scheduled a bark audit after lunch ([Bark Ledger][5]).
One terrier mentioned a missing sock appendix ([Sock Appendix][6]).

[1]: https://example.test/birds/crumbs "Crumb Hearing"
[2]: https://example.test/birds/moonlight "Moonlight Precedent"
[3]: https://example.test/cats/purr-manual "Purr Manual"
[5]: https://example.test/dogs/bark-ledger "Bark Ledger"
[6]: https://example.test/dogs/sock-appendix "Sock Appendix"
`);
    expect(dogsResult.content).not.toContain("[4]:");
    expect(dogsResult.content.slice(dogsResult.cursorOffset)).toBe(`

[1]: https://example.test/birds/crumbs "Crumb Hearing"
[2]: https://example.test/birds/moonlight "Moonlight Precedent"
[3]: https://example.test/cats/purr-manual "Purr Manual"
[5]: https://example.test/dogs/bark-ledger "Bark Ledger"
[6]: https://example.test/dogs/sock-appendix "Sock Appendix"
`);
  });

  it("appends references when the existing document has no trailing reference block", () => {
    const result = pasteMergeMarkdown("Plain existing body\n", cats);

    expect(result.content).toContain("Plain existing body\n\n## Cat Operations");
    expect(result.content).toContain("([Purr Manual][1])");
    expect(result.content).toContain("([Laser Memo][2])");
    expect(result.content).toContain('[1]: https://example.test/cats/purr-manual "Purr Manual"');
  });

  it("appends pasted text that has no reference definitions", () => {
    const result = pasteMergeMarkdown(birds, "A goose arrived with a tiny clipboard.\n");

    expect(result.content).toBe(`## Bird Committee Notes

The sparrow filed a tiny incident report about crumbs ([Feather Court][1]).
An owl objected from the chandelier and cited moonlight precedent ([Night Desk][2]).

A goose arrived with a tiny clipboard.

[1]: https://example.test/birds/crumbs "Crumb Hearing"
[2]: https://example.test/birds/moonlight "Moonlight Precedent"
`);
  });

  it("renumbers orphaned pasted in-text references without creating definitions", () => {
    const result = pasteMergeMarkdown(
      "Existing ([Link][4]).\n\n[4]: https://example.test/existing\n",
      "Pasted orphan ([Missing][1]).\n",
    );

    expect(result.content).toBe(`Existing ([Link][4]).

Pasted orphan ([Missing][5]).

[4]: https://example.test/existing
`);
    expect(result.content).not.toContain("[5]:");
  });

  it("uses the highest existing reference label when numbering has gaps", () => {
    const result = pasteMergeMarkdown(
      "Existing ([First][1]) and ([Tenth][10]).\n\n[1]: https://example.test/one\n",
      "Pasted ([Next][1]).\n\n[1]: https://example.test/next\n",
    );

    expect(result.content).toContain("Pasted ([Next][11]).");
    expect(result.content).toContain("[11]: https://example.test/next");
  });

  it("treats blank lines between trailing definitions as part of the final reference block", () => {
    const result = pasteMergeMarkdown(
      "Existing ([One][1]) and ([Two][2]).\n\n[1]: https://example.test/one\n\n[2]: https://example.test/two\n",
      "Pasted ([Next][1]).\n\n[1]: https://example.test/next\n",
    );

    expect(result.content).toBe(`Existing ([One][1]) and ([Two][2]).

Pasted ([Next][3]).

[1]: https://example.test/one

[2]: https://example.test/two
[3]: https://example.test/next
`);
  });

  it("ignores reference definitions and labels inside fenced code blocks", () => {
    const result = pasteMergeMarkdown(
      "Existing ([Known][1]).\n\n```md\n[50]: https://example.test/code\n[Code][60]\n```\n\n[1]: https://example.test/known\n",
      "Pasted ([Real][1]).\n\n```md\n[Code][2]\n[2]: https://example.test/code\n```\n\n[1]: https://example.test/real\n",
    );

    expect(result.content).toContain("Pasted ([Real][2]).");
    expect(result.content).toContain("[2]: https://example.test/real");
    expect(result.content).toContain("[Code][2]");
    expect(result.content).toContain("[2]: https://example.test/code");
    expect(result.content).not.toContain("[51]:");
  });

  it("places the cursor after the pasted body and before final definitions", () => {
    const result = pasteMergeMarkdown(birds, dogs);

    expect(result.content.slice(0, result.cursorOffset)).toContain("Sock Appendix][4]).");
    expect(result.content.slice(result.cursorOffset).startsWith("\n\n[1]:")).toBe(true);
  });
});
