mod config;

fn main() -> miette::Result<()> {
    let config = config::parse_config("example.kdl")?;

    println!("{:?}", config);
    Ok(())
}
