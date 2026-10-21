# 06: Enrollment codes

**Status:** todo · **Crate:** erbridge-core · **Blocked by:** 04

**What to build:** single-use enrollment codes and the client side.

- `serve`: codes are extra PSK candidates; a match burns the code, creates the
  tenant, persists it, sends `{name, token, sni}` inside the channel.
- `reverse::enroll::enroll(server, code) -> Credentials`.

## Acceptance

- A valid code yields credentials that then connect as the new tenant.
- The same code a second time fails; an expired code fails.
- Two concurrent redemptions of one code: exactly one succeeds.
- A code never authenticates as an existing tenant, and a tenant token never
  redeems as a code.
- Generated names and tokens are random and unique across many enrollments.
