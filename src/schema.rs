use crate::db::{
    connection_busy_timeout, connection_dqs, connection_enable_foreign_keys, connection_wal,
    quick_check,
};
use miette::{Context, IntoDiagnostic};
use rusqlite::{named_params, Connection, OptionalExtension};
use std::path::Path;

pub(crate) struct Database {
    pub(crate) conn: Connection,
}

impl Database {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    pub fn queue_url(&self, url: reqwest::Url) -> miette::Result<Option<u64>> {
        let url = String::from(url);
        let should_fetch = true;
        let id: Option<u64> = self
            .conn
            .query_row(
                r#"
                    INSERT INTO link (url, should_fetch)
                    VALUES (:url, :should_fetch)
                    ON CONFLICT DO NOTHING
                    RETURNING id
                "#,
                named_params! {":url": url, ":should_fetch": should_fetch},
                |row| row.get(0),
            )
            .optional()
            .into_diagnostic()?;
        Ok(id)
    }
}

// --- //

pub(crate) fn connect(path: &Path) -> miette::Result<Database> {
    let conn = Connection::open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot open database {}", path.to_string_lossy()))?;

    quick_check(&conn)?;

    connection_wal(&conn)?;
    connection_busy_timeout(&conn, humantime::parse_duration("100ms").unwrap())?;
    connection_enable_foreign_keys(&conn)?;
    connection_dqs(&conn)?;

    ensure_schema(&conn)?;

    Ok(Database::new(conn))
}

fn user_version(conn: &Connection) -> miette::Result<u64> {
    conn.query_row("SELECT user_version FROM pragma_user_version", [], |row| {
        row.get(0)
    })
    .into_diagnostic()
    .wrap_err("Could not query PRAGMA user_version")
}

pub(crate) fn ensure_schema(conn: &Connection) -> miette::Result<()> {
    // a new database starts at user_version 0

    if user_version(conn)? == 0 {
        conn.execute_batch(r#"
            CREATE TABLE link (id INTEGER PRIMARY KEY AUTOINCREMENT, url text NOT NULL, should_fetch int NOT NULL DEFAULT 0);
            CREATE UNIQUE INDEX link_url_uidx ON link(url);
            CREATE VIEW fetch_queue AS SELECT id, url FROM link WHERE should_fetch = 1 AND NOT EXISTS (SELECT * FROM request WHERE link_id = link.id);
            CREATE TABLE sitemap (source int NOT NULL REFERENCES link(id), target int NOT NULL REFERENCES link(id), PRIMARY KEY (source, target));
            CREATE TABLE request (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id int NOT NULL REFERENCES link(id),
                method text NOT NULL,
                url text NOT NULL,
                headers json NOT NULL,
                body blob
            );
            CREATE INDEX request_link_id ON request(link_id);
            CREATE TABLE response (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id int NOT NULL REFERENCES link(id),
                request_id int NOT NULL REFERENCES request(id),
                status_code text NOT NULL,
                url text NOT NULL,
                headers json NOT NULL,
                encoding text NOT NULL,
                body blob NOT NULL,
                parsed int NOT NULL DEFAULT 0
            );
            CREATE INDEX response_is_parsed ON response(parsed) WHERE parsed = 0;
            CREATE VIEW parse_queue AS SELECT id FROM response WHERE parsed = 0;
            PRAGMA user_version = 1;
        "#).into_diagnostic()?;
    }

    if user_version(conn)? == 1 {
        conn.execute_batch( r#"
            DROP VIEW parse_queue;
            CREATE VIEW parse_queue AS SELECT id FROM response WHERE parsed = 0 AND body IS NOT NULL;
            PRAGMA user_version = 2;
        "# ).into_diagnostic()?;
    }

    if user_version(conn)? == 2 {
        conn.execute_batch( r#"
            DROP VIEW parse_queue;
            CREATE VIEW parse_queue AS SELECT id, url FROM response WHERE parsed = 0 AND body IS NOT NULL;
            PRAGMA user_version = 3;
        "# ).into_diagnostic()?;
    }

    if user_version(conn)? == 3 {
        conn.execute_batch(
            r#"
            CREATE INDEX response_request_id_idx ON response(request_id); --> request(id)
            CREATE INDEX response_link_id_idx ON response(link_id); --> link(id)
            CREATE INDEX sitemap_target_idx ON sitemap(target); --> link(id)
            PRAGMA user_version = 4;
        "#,
        )
        .into_diagnostic()?;
    }

    Ok(())
}
