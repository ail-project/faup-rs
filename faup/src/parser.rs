use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "grammar.pest"]
pub(crate) struct UrlParser;
