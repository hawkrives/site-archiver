#![allow(dead_code)]

use std::{collections::HashMap, path::Path};

use miette::{Context, IntoDiagnostic};

#[derive(knuffel::Decode, Debug)]
pub(crate) struct SiteConfig {
    #[knuffel(argument)]
    pub(crate) name: String,
    #[knuffel(child)]
    pub(crate) start_url: StartUrl,
    #[knuffel(child)]
    pub(crate) fetch_delay: FetchDelay,
    #[knuffel(children(name = "include-rule"))]
    pub(crate) include_rules: Vec<SiteRule>,
    #[knuffel(children(name = "exclude-rule"))]
    pub(crate) exclude_rules: Vec<SiteRule>,
    #[knuffel(child)]
    pub(crate) authentication: Option<Authentication>,
    #[knuffel(children(name = "unauthorized-when"))]
    pub(crate) unauthorized_heuristics: Vec<UnauthorizedHeuristic>,
}

#[derive(knuffel::Decode, Debug)]
pub(crate) struct Authentication {
    #[knuffel(property, str)]
    pub(crate) method: reqwest::Method,
    #[knuffel(property, str)]
    pub(crate) action: reqwest::Url,
    #[knuffel(children(name = "field"))]
    pub(crate) fields: Vec<AuthenticationField>,
}

#[derive(knuffel::Decode, Debug)]
pub(crate) struct AuthenticationField(#[knuffel(properties)] HashMap<String, String>);

#[derive(knuffel::Decode, Debug)]
pub(crate) struct StartUrl(#[knuffel(argument, str)] pub(crate) reqwest::Url);

#[derive(knuffel::Decode, Debug)]
pub(crate) struct FetchDelay(#[knuffel(argument, str)] pub(crate) humantime::Duration);

impl Default for FetchDelay {
    fn default() -> Self {
        Self("0.5s".parse().unwrap())
    }
}

#[derive(knuffel::Decode, Debug)]
pub(crate) struct SiteRule {
    #[knuffel(argument, str)]
    pub(crate) path: globset::Glob,
}

#[derive(knuffel::Decode, Debug)]
pub(crate) struct UnauthorizedHeuristic {
    #[knuffel(property)]
    pub(crate) body: Option<String>,
}

pub(crate) fn parse_config(path: &Path) -> miette::Result<Vec<SiteConfig>> {
    let text = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot read {:?}", path))?;

    Ok(knuffel::parse(&path.to_string_lossy(), &text)?)
}
