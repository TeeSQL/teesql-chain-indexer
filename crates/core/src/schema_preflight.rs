//! Startup schema verification.
//!
//! The chain-indexer does NOT run migrations at startup — `provision.sql`
//! is operator-applied per spec §3.1, and `EventStore::new` documents
//! exactly that. The downside is that a column added to a materializer's
//! `INSERT` (e.g. `cluster_members.wg_endpoint` for GAP-W1-005) crashes
//! at first event, not at startup, on any deployment whose operator
//! forgot to re-apply `provision.sql` after the upgrade. The error
//! surfaces as an opaque sqlx `column "wg_endpoint" of relation
//! "cluster_members" does not exist` deep inside the ingest loop, which
//! is exactly the kind of late-bind failure mode that makes upgrades
//! brittle.
//!
//! [`verify_required_schema`] runs a single `information_schema` probe
//! at boot, before any chain ingestor spawns, and bails with a clear
//! "migration required — re-apply deploy/provision.sql" message if the
//! materializers' write set is missing any of the columns this build
//! depends on. The check is cheap (one `SELECT` against a system
//! catalog) and catches the entire class of "operator upgraded the
//! image but forgot the schema re-apply" failures in one place.

use sqlx::{PgPool, Row};

/// Columns this indexer build writes to. Add entries whenever a
/// materializer starts writing a new column so the startup check
/// keeps up with the on-disk schema contract.
///
/// Each entry is `(table_name, column_name, "since-when" tag)`. The
/// since-tag is shown in the error message so operators can correlate
/// the missing column back to the release notes that introduced it.
const REQUIRED_COLUMNS: &[(&str, &str, &str)] = &[
    // Phase 1 fabric cross-boundary — `MemberWgPubkeySet` materializer.
    ("cluster_members", "wg_pubkey_hex", "wg-pubkey-events"),
    // GAP-W1-005 — explicit `wg_endpoint` field surfaced to fabric.
    ("cluster_members", "wg_endpoint", "GAP-W1-005"),
];

/// Verify the database has every column this indexer build writes to.
///
/// Returns `Ok(())` when every required column exists. Returns an error
/// listing all missing columns and pointing operators at the canonical
/// fix when one or more is absent — re-applying `deploy/provision.sql`
/// against the monitor cluster's primary. The error is emitted at
/// startup so the operator sees it instead of an opaque ingest-loop
/// crash on the next on-chain event.
pub async fn verify_required_schema(pool: &PgPool) -> anyhow::Result<()> {
    let rows = sqlx::query(
        "SELECT table_name, column_name \
         FROM information_schema.columns \
         WHERE table_schema = 'public' \
           AND (table_name, column_name) IN (\
             SELECT * FROM UNNEST($1::text[], $2::text[]) \
           )",
    )
    .bind(
        REQUIRED_COLUMNS
            .iter()
            .map(|(t, _, _)| *t)
            .collect::<Vec<_>>(),
    )
    .bind(
        REQUIRED_COLUMNS
            .iter()
            .map(|(_, c, _)| *c)
            .collect::<Vec<_>>(),
    )
    .fetch_all(pool)
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "schema preflight: information_schema probe failed: {e} — \
             check that the indexer's database role has SELECT on \
             information_schema (default for any LOGIN role) and that \
             the connection pool is healthy"
        )
    })?;

    let mut present = std::collections::HashSet::new();
    for row in &rows {
        let t: String = row.try_get("table_name")?;
        let c: String = row.try_get("column_name")?;
        present.insert((t, c));
    }

    let missing: Vec<&(&str, &str, &str)> = REQUIRED_COLUMNS
        .iter()
        .filter(|(t, c, _)| !present.contains(&((*t).to_string(), (*c).to_string())))
        .collect();

    if missing.is_empty() {
        tracing::info!(
            checked = REQUIRED_COLUMNS.len(),
            "schema preflight: all required columns present"
        );
        return Ok(());
    }

    let mut detail = String::new();
    for (table, column, since) in &missing {
        detail.push_str(&format!("\n  - {table}.{column} (since: {since})"));
    }
    anyhow::bail!(
        "schema preflight: indexer build requires columns the database \
         is missing — re-apply deploy/provision.sql against the monitor \
         cluster's primary, then restart this indexer. Missing:{detail}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_columns_are_unique_per_table_column_pair() {
        // Guard against accidentally listing the same (table, column)
        // twice — duplicates would still pass the runtime check but
        // signal a confused intent in this registry.
        let mut seen = std::collections::HashSet::new();
        for (t, c, _) in REQUIRED_COLUMNS {
            assert!(
                seen.insert((t, c)),
                "duplicate REQUIRED_COLUMNS entry: {t}.{c}"
            );
        }
    }

    #[test]
    fn required_columns_uses_snake_case() {
        // The column-name strings hit `information_schema.columns`
        // verbatim, which stores unquoted identifiers in lower case.
        // A camelCase entry here would silently never match.
        for (_, c, _) in REQUIRED_COLUMNS {
            for ch in c.chars() {
                assert!(
                    ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_',
                    "REQUIRED_COLUMNS entry `{c}` must be lower-snake_case"
                );
            }
        }
    }

    // The actual database-backed test for verify_required_schema is in
    // crates/teesql-views/tests/replay_tests.rs alongside the other
    // DATABASE_URL-gated apply-path tests — it requires a real Postgres
    // fixture seeded from deploy/provision.sql and a mutated copy of
    // that fixture with the column dropped, both of which the test
    // harness in that file already builds.
}
