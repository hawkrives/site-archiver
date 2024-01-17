use miette::{miette, Context, IntoDiagnostic};
use rusqlite::Connection;

/// Turns on write ahead logging
///
/// Reduces contention and improves write performance.  WAL is
/// [described in the SQLite documentation](https://www.sqlite.org/wal.html).
pub(crate) fn connection_wal(conn: &Connection) -> miette::Result<String> {
    conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
        .into_diagnostic()
        .wrap_err("Could not execute PRAGMA journal_mode=WAL")
}

/// Sets a short busy timeout
///
/// **Parameters**
/// - `duration` How long to wait
///
/// When another thread or process has locked the database, SQLite
/// immediately raises [BusyError].  Changing the [busy
/// timeout](https://www.sqlite.org/c3ref/busy_timeout.html) gives
/// a grace period during which SQLite retries.
pub(crate) fn connection_busy_timeout(
    conn: &Connection,
    duration: std::time::Duration,
) -> miette::Result<()> {
    conn.busy_timeout(duration)
        .into_diagnostic()
        .wrap_err("Could not set busy_timeout")
}

/// Enables foreign key constraints
///
/// [Foreign keys](https://www.sqlite.org/foreignkeys.html) need to
/// [be enabled](https://www.sqlite.org/foreignkeys.html#fk_enable)
/// to have an effect.
pub(crate) fn connection_enable_foreign_keys(conn: &Connection) -> miette::Result<()> {
    conn.pragma_update(None, "foreign_keys", "ON")
        .into_diagnostic()
        .wrap_err("Could not execute PRAGMA foreign_keys=ON")
}

/// Double quotes are for identifiers only, not strings
///
/// Turns off [allowing double quoted strings](https://www.sqlite.org/quirks.html#dblquote)
/// if they don't match any identifier (column/table names etc), making it an error
/// to use double quotes around strings.  SQL strings use single quotes.
pub(crate) fn connection_dqs(conn: &Connection) -> miette::Result<()> {
    conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)
        .into_diagnostic()
        .wrap_err("Could not disable double-quoted strings in DDL")?;
    conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DQS_DML, false)
        .into_diagnostic()
        .wrap_err("Could not disable double-quoted strings in DML")?;
    Ok(())
}

pub(crate) fn quick_check(conn: &Connection) -> miette::Result<()> {
    let quick_check: String = conn
        .query_row("SELECT quick_check FROM pragma_quick_check", [], |row| {
            row.get(0)
        })
        .into_diagnostic()
        .wrap_err("Could not query PRAGMA quick_check")?;

    match quick_check.as_str() {
        "ok" => Ok(()),
        _ => Err(miette!("quick_check did not return 'ok'")),
    }
}

pub(crate) fn integrity_check(conn: &Connection) -> miette::Result<()> {
    let integrity_check: String = conn
        .query_row(
            "SELECT integrity_check FROM pragma_integrity_check",
            [],
            |row| row.get(0),
        )
        .into_diagnostic()
        .wrap_err("Could not query PRAGMA integrity_check")?;

    match integrity_check.as_str() {
        "ok" => Ok(()),
        _ => Err(miette!("integrity_check did not return 'ok'")),
    }
}
