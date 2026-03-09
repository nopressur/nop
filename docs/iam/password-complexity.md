# Password Complexity Policy

Status: Developed

## Objectives

- Define the password complexity policy used by the admin and profile SPAs.
- Provide a single debug-only switch to disable the policy for testing; production must always enforce it.
- Ensure client-side validation (admin/profile) and server-side plaintext validation stay aligned.

## Technical Details

### Configuration

The policy itself is not configurable. Requirements are fixed.

Configuration provides a single debug-only switch to disable the policy for testing:

```yaml
users:
  local:
    password_complexity_disabled: false
```

Validation rules:

- In debug builds, `password_complexity_disabled: true` is allowed for testing.
- In release builds, the flag is ignored (treated as `false`) and an info log message is emitted if it is set to `true`. Production must never run with the policy disabled.

### Policy Evaluation

The policy applies to the raw password value exactly as entered (no trimming or normalization).
Complexity checks are Unicode-aware:

- Lowercase: at least one character with the Unicode `Lowercase` property.
- Uppercase: at least one character with the Unicode `Uppercase` property.
- Number: at least one character with the Unicode `Decimal_Number` property.
- Length: at least 8 Unicode scalar values.

Script handling:

- **Uncased-only**: If the password contains no cased letters (`Uppercase` or `Lowercase`),
  the case requirements are skipped. The effective requirement becomes:
  - Length (>= 8)
  - At least one Unicode letter (alphabetic)
  - At least one Unicode decimal digit
- **Cased-only**: If the password contains cased letters and no uncased letters, the full case
  requirements apply (lowercase + uppercase + number + length).
- **Mixed cased + uncased**: If the password includes both cased and uncased letters, the case
  requirement is treated as satisfied (no need to prove both upper and lower); number + length still apply.

Other characters are allowed but do not satisfy the required categories.

#### UI Messaging Guidance

The UI note should be simple and only appear once the user has typed more than three characters
and the password is still invalid.

Note text (verbatim, by case):

- Uncased-only: “Password needs to be at least 8 long with letters and numbers.”
- Cased-only: “Password needs to be at least 8 long with lowercase and uppercase letters and numbers.”
- Mixed cased + uncased: “Password needs to be at least 8 long with letters and numbers.”

The Save/Submit button must remain disabled until the password satisfies the policy or the policy
is disabled via configuration (debug builds only).

### Admin SPA Requirements

The admin user management UI must validate passwords before hashing:

- Apply the policy when creating a user and when resetting a password.
- Disable submit (and show inline errors) until the policy is satisfied.
- Use the runtime config to render the requirement text so UI and backend share the same policy.

### Profile SPA Requirements

The profile password module must validate the new password before hashing:

- Apply the policy on `new password` and `confirm new password` fields.
- Block submission until the policy is satisfied.
- Use the runtime config from the login/profile SPA shell.

### Backend Enforcement

Server-side enforcement applies only where plaintext passwords are present:

- CLI flows (`nop user add` / `nop user password`) and auto-bootstrap must validate plaintext passwords against the policy before hashing.
- SPA flows that send only front-end hashes rely on client-side validation.

### Errors and Messaging

When a plaintext password fails the policy, handlers must return the endpoint's existing error
envelope with a message that explains the policy (length + required character classes). The admin
and profile SPAs should surface these messages alongside their inline validation.
