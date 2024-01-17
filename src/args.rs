use std::path::PathBuf;

use argp::FromArgs;

/// Archive a website, configured by config file.
#[derive(FromArgs, PartialEq, Debug)]
pub(crate) struct Args {
    /// be verbose.
    #[argp(switch, short = 'v', global)]
    pub(crate) verbose: bool,

    /// which config file to use [default: sites.kdl]
    #[argp(
        option,
        global,
        default = "PathBuf::from(\"sites.kdl\")",
        arg_name = "file"
    )]
    pub(crate) config: PathBuf,

    /// which database to use [default: config filename + .sqlite3]
    #[argp(option, global, arg_name = "file")]
    pub(crate) database: Option<PathBuf>,

    #[argp(subcommand)]
    pub(crate) command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
pub(crate) enum SubCommand {
    Crawl(SubCommandCrawl),
    Explore(SubCommandExplore),
    Fetch(SubCommandFetch),
    Insert(SubCommandInsert),
    ValidateConfig(SubCommandValidateConfig),
    ValidateDatabase(SubCommandValidateDatabase),
}

/// Crawl a website, archiving each response into a local sqlite database.
#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand, name = "crawl")]
pub(crate) struct SubCommandCrawl {
    /// exit after the first fetch/parse batch completes
    #[argp(switch)]
    pub(crate) once: Option<bool>,

    /// pages to fetch in a single batch
    #[argp(option, arg_name = "n")]
    pub(crate) fetch_count: Option<usize>,

    /// pages to parse in a single batch
    #[argp(option, arg_name = "n")]
    pub(crate) parse_count: Option<usize>,
}

/// Fetch items from the fetch queue.
#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand, name = "fetch")]
pub(crate) struct SubCommandFetch {
    /// how many documents to parse [default: all]
    #[argp(option, arg_name = "count")]
    pub(crate) count: Option<u64>,
}

/// Explore the unparsed queue, adding undiscovered links to the fetch queue.
#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand, name = "explore")]
pub(crate) struct SubCommandExplore {
    /// how many documents to parse [default: all]
    #[argp(option, arg_name = "count")]
    pub(crate) count: Option<u64>,
}

/// Insert a new URL into the fetch queue
#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand, name = "insert")]
pub(crate) struct SubCommandInsert {
    /// the URL to add to the queue
    #[argp(positional)]
    pub(crate) url: String,
}

/// Validate a config file.
#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand, name = "validate-config")]
pub(crate) struct SubCommandValidateConfig {}

/// Validate a database file.
#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand, name = "validate-db")]
pub(crate) struct SubCommandValidateDatabase {}
