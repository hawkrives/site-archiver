use db::integrity_check;
use miette::IntoDiagnostic;

mod args;
mod config;
mod db;
mod schema;

#[tokio::main]

async fn main() -> miette::Result<()> {
    let args = {
        let mut args: crate::args::Args = argp::parse_args_or_exit(argp::DEFAULT);
        match args.config.extension() {
            Some(_) => {}
            None => {
                args.config.set_extension("kdl");
            }
        }
        args.database = Some(args.config.with_extension("sqlite3"));
        args
    };

    let config = config::parse_config(&args.config)?;
    let db = schema::connect(&args.database.clone().unwrap())?;

    match args.command {
        crate::args::SubCommand::Crawl(crate::args::SubCommandCrawl {
            once,
            fetch_count,
            parse_count,
        }) => todo!(),

        crate::args::SubCommand::Explore(crate::args::SubCommandExplore { count }) => {
            todo!()
        }

        crate::args::SubCommand::Insert(crate::args::SubCommandInsert { url }) => {
            db.queue_url(url.parse().into_diagnostic()?)?;
        }

        crate::args::SubCommand::ValidateConfig(crate::args::SubCommandValidateConfig {}) => {
            // loading a config validates the config
            for site in config {
                println!("{:?}", site);
                println!();
            }
        }

        crate::args::SubCommand::ValidateDatabase(crate::args::SubCommandValidateDatabase {}) => {
            integrity_check(&db.conn)?;
            println!("validated database {}", args.database.unwrap().display());
        }
    }
    Ok(())
}
