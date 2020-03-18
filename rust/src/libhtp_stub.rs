/// This module exists just to ensure that http_parser, along
/// with libhtp is linked into the output library as its not
/// used anywhere yet.
#[allow(unused_imports)]
use http_parser;