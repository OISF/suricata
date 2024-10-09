use crate::{
    bstr::Bstr,
    config::{DecoderConfig, HtpUnwanted},
    log::Logger,
    parsers::{credentials, fragment, hostname, parse_hostport, path, port, query, scheme},
    urlencoded::{decode_uri_inplace, decode_uri_with_flags, path_decode_uri_inplace},
    utf8_decoder::decode_and_validate_inplace,
    util::{convert_port, FlagOperations, HtpFlags},
};
use nom::{combinator::opt, sequence::tuple};

/// URI structure. Each of the fields provides access to a single
/// URI element. Where an element is not present in a URI, the
/// corresponding field will be set to NULL or -1, depending on the
/// field type.
#[derive(Clone)]
pub struct Uri {
    /// Decoder configuration
    pub cfg: DecoderConfig,
    /// Scheme, e.g., "http".
    pub scheme: Option<Bstr>,
    /// Username.
    pub username: Option<Bstr>,
    /// Password.
    pub password: Option<Bstr>,
    /// Hostname.
    pub hostname: Option<Bstr>,
    /// Port, as string.
    pub port: Option<Bstr>,
    /// Port, as number. This field will be None if there was
    /// no port information in the URI or the port information
    /// was invalid (e.g., it's not a number or it falls out of range.
    pub port_number: Option<u16>,
    /// The path part of this URI.
    pub path: Option<Bstr>,
    /// Query string.
    pub query: Option<Bstr>,
    /// Fragment identifier. This field will rarely be available in a server-side
    /// setting, but it's not impossible to see it.
    pub fragment: Option<Bstr>,
}

impl std::fmt::Debug for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Uri")
            .field("scheme", &self.scheme)
            .field("username", &self.username)
            .field("password", &self.password)
            .field("hostname", &self.hostname)
            .field("port", &self.port)
            .field("port_number", &self.port_number)
            .field("path", &self.path)
            .field("query", &self.query)
            .field("fragment", &self.fragment)
            .finish()
    }
}

impl Default for Uri {
    /// Create an empty Uri struct.
    fn default() -> Self {
        Self {
            cfg: DecoderConfig::default(),
            scheme: None,
            username: None,
            password: None,
            hostname: None,
            port: None,
            port_number: None,
            path: None,
            query: None,
            fragment: None,
        }
    }
}

impl Uri {
    /// Create an empty Uri struct but with the given DecoderCfg
    pub fn with_config(cfg: DecoderConfig) -> Self {
        Self {
            cfg,
            scheme: None,
            username: None,
            password: None,
            hostname: None,
            port: None,
            port_number: None,
            path: None,
            query: None,
            fragment: None,
        }
    }

    /// Normalize uri scheme.
    pub fn normalized_scheme(&self) -> Option<Bstr> {
        if let Some(mut scheme) = self.scheme.clone() {
            scheme.make_ascii_lowercase();
            Some(scheme)
        } else {
            None
        }
    }

    /// Normalize uri username.
    pub fn normalized_username(&self, flags: &mut u64) -> Option<Bstr> {
        if let Some(username) = self.username.as_ref() {
            decode_uri_with_flags(&self.cfg, flags, username.as_slice()).ok()
        } else {
            None
        }
    }

    /// Normalize uri password.
    pub fn normalized_password(&self, flags: &mut u64) -> Option<Bstr> {
        if let Some(password) = self.password.as_ref() {
            decode_uri_with_flags(&self.cfg, flags, password.as_slice()).ok()
        } else {
            None
        }
    }

    /// Normalize uri hostname.
    pub fn normalized_hostname(&self, flags: &mut u64) -> Option<Bstr> {
        if let Some(hostname) = self.hostname.as_ref() {
            let mut normalized_hostname =
                decode_uri_with_flags(&self.cfg, flags, hostname.as_slice()).ok()?;
            normalized_hostname.make_ascii_lowercase();
            // Remove dots from the end of the string.
            while normalized_hostname.last() == Some(&(b'.')) {
                normalized_hostname.pop();
            }
            Some(normalized_hostname)
        } else {
            None
        }
    }

    /// Normalize uri port.
    pub fn normalized_port(&self, flags: &mut u64) -> Option<u16> {
        if let Some(port) = self.port.as_ref() {
            let normalized_port = convert_port(port.as_slice());
            if normalized_port.is_none() {
                // Failed to parse the port number.
                flags.set(HtpFlags::HOSTU_INVALID);
            }
            normalized_port
        } else {
            None
        }
    }

    /// Normalize uri fragment.
    pub fn normalized_fragment(&self, flags: &mut u64) -> Option<Bstr> {
        if let Some(fragment) = self.fragment.as_ref() {
            decode_uri_with_flags(&self.cfg, flags, fragment).ok()
        } else {
            None
        }
    }

    /// Normalize uri path.
    pub fn normalized_path(&self, flags: &mut u64, status: &mut HtpUnwanted) -> Option<Bstr> {
        if let Some(mut path) = self.path.clone() {
            // Decode URL-encoded (and %u-encoded) characters, as well as lowercase,
            // compress separators and convert backslashes.
            // Ignore result.
            path_decode_uri_inplace(&self.cfg, flags, status, &mut path);
            // Handle UTF-8 in the path. Validate it first, and only save it if cfg specifies it
            decode_and_validate_inplace(&self.cfg, flags, status, &mut path);
            // RFC normalization.
            normalize_uri_path_inplace(&mut path);
            Some(path)
        } else {
            None
        }
    }

    /// Parses request URI, making no attempt to validate the contents.
    ///
    /// It attempts, but is not guaranteed to successfully parse out a scheme, username, password, hostname, port, query, and fragment.
    /// Note: only attempts to extract a username, password, and hostname and subsequently port if it successfully parsed a scheme.
    pub fn parse_uri(&mut self, input: &[u8]) {
        let res = tuple((
            opt(tuple((
                scheme(),
                opt(credentials()),
                opt(tuple((hostname(), opt(port())))),
            ))),
            opt(path()),
            opt(query()),
            opt(fragment()),
        ))(input);
        if let Ok((_, (scheme_authority, path, query, fragment))) = res {
            if let Some(path) = path {
                self.path = Some(Bstr::from(path));
            }
            if let Some(query) = query {
                self.query = Some(Bstr::from(query));
            }
            if let Some(fragment) = fragment {
                self.fragment = Some(Bstr::from(fragment));
            }
            if let Some((scheme, authority, hostname_port)) = scheme_authority {
                self.scheme = Some(Bstr::from(scheme));
                if let Some((username, password)) = authority {
                    self.username = Some(Bstr::from(username));
                    if let Some(password) = password {
                        self.password = Some(Bstr::from(password));
                    }
                }
                if let Some((hostname, port)) = hostname_port {
                    self.hostname = Some(Bstr::from(hostname));
                    if let Some(port) = port {
                        self.port = Some(Bstr::from(port));
                    }
                }
            }
        }
    }

    /// Parses hostport provided in the URI.
    pub fn parse_uri_hostport(&mut self, hostport: &Bstr, flags: &mut u64) {
        if let Ok((_, (host, port_nmb, mut valid))) = parse_hostport(hostport) {
            let hostname = &host.to_ascii_lowercase();
            self.hostname = Some(Bstr::from(hostname.as_slice()));
            if let Some((port, port_nmb)) = port_nmb {
                self.port = Some(Bstr::from(port));
                if let Some(num) = port_nmb {
                    self.port_number = Some(num);
                } else {
                    valid = false;
                }
            }
            if !valid {
                flags.set(HtpFlags::HOSTU_INVALID)
            }
        }
    }

    /// Generate a normalized uri string.
    pub fn generate_normalized_uri(
        &self,
        mut logger: Option<Logger>,
    ) -> (Option<Bstr>, Option<Bstr>) {
        // On the first pass determine the length of the final bstrs
        let mut partial_len = 0usize;
        let mut complete_len = 0usize;
        complete_len = complete_len.wrapping_add(
            self.scheme
                .as_ref()
                .map(|scheme| scheme.len() + 3)
                .unwrap_or(0),
        ); // '://'
        complete_len = complete_len.wrapping_add(
            self.username
                .as_ref()
                .map(|username| username.len())
                .unwrap_or(0),
        );
        complete_len = complete_len.wrapping_add(
            self.password
                .as_ref()
                .map(|password| password.len())
                .unwrap_or(0),
        );
        if self.username.is_some() || self.password.is_some() {
            complete_len = complete_len.wrapping_add(2); // ':' and '@'
        }
        complete_len = complete_len.wrapping_add(
            self.hostname
                .as_ref()
                .map(|hostname| hostname.len())
                .unwrap_or(0),
        );
        complete_len =
            complete_len.wrapping_add(self.port.as_ref().map(|port| port.len()).unwrap_or(0)); // ':'
        partial_len =
            partial_len.wrapping_add(self.path.as_ref().map(|path| path.len()).unwrap_or(0));
        partial_len = partial_len.wrapping_add(
            self.query
                .as_ref()
                .map(|query| query.len() + 1)
                .unwrap_or(0),
        ); // ?
        partial_len = partial_len.wrapping_add(
            self.fragment
                .as_ref()
                .map(|fragment| fragment.len() + 1)
                .unwrap_or(0),
        ); // #
        complete_len = complete_len.wrapping_add(partial_len);
        // On the second pass construct the string
        let mut normalized_uri = Bstr::with_capacity(complete_len);
        let mut partial_normalized_uri = Bstr::with_capacity(partial_len);

        if let Some(scheme) = self.scheme.as_ref() {
            normalized_uri.add(scheme.as_slice());
            normalized_uri.add("://");
        }
        if self.username.is_some() || self.password.is_some() {
            if let Some(username) = self.username.as_ref() {
                normalized_uri.add(username.as_slice());
            }
            normalized_uri.add(":");
            if let Some(password) = self.password.as_ref() {
                normalized_uri.add(password.as_slice());
            }
            normalized_uri.add("@");
        }
        if let Some(hostname) = self.hostname.as_ref() {
            normalized_uri.add(hostname.as_slice());
        }
        if let Some(port) = self.port.as_ref() {
            normalized_uri.add(":");
            normalized_uri.add(port.as_slice());
        }
        if let Some(mut path) = self.path.clone() {
            // Path is already decoded when we parsed the uri in transaction, only decode once more
            if self.cfg.double_decode_normalized_path {
                let path_len = path.len();
                let _ = decode_uri_inplace(&self.cfg, &mut path);
                if path_len > path.len() {
                    if let Some(logger) = logger.as_mut() {
                        htp_warn!(
                            logger,
                            HtpLogCode::DOUBLE_ENCODED_URI,
                            "URI path is double encoded"
                        );
                    }
                }
            }
            partial_normalized_uri.add(path.as_slice());
        }
        if let Some(mut query) = self.query.clone() {
            let _ = decode_uri_inplace(&self.cfg, &mut query);
            if self.cfg.double_decode_normalized_query {
                let query_len = query.len();
                let _ = decode_uri_inplace(&self.cfg, &mut query);
                if query_len > query.len() {
                    if let Some(logger) = logger.as_mut() {
                        htp_warn!(
                            logger,
                            HtpLogCode::DOUBLE_ENCODED_URI,
                            "URI query is double encoded"
                        );
                    }
                }
            }
            partial_normalized_uri.add("?");
            partial_normalized_uri.add(query.as_slice());
        }
        if let Some(fragment) = self.fragment.as_ref() {
            partial_normalized_uri.add("#");
            partial_normalized_uri.add(fragment.as_slice());
        }
        normalized_uri.add(partial_normalized_uri.as_slice());
        if !normalized_uri.is_empty() {
            if !partial_normalized_uri.is_empty() {
                (Some(partial_normalized_uri), Some(normalized_uri))
            } else {
                (None, Some(normalized_uri))
            }
        } else {
            (None, None)
        }
    }
}

/// Normalize URI path in place. This function implements the remove dot segments algorithm
/// specified in RFC 3986, section 5.2.4.
fn normalize_uri_path_inplace(s: &mut Bstr) {
    let mut out = Vec::<&[u8]>::with_capacity(10);
    s.as_slice()
        .split(|c| *c == b'/')
        .for_each(|segment| match segment {
            b"." => {}
            b".." => {
                if !(out.len() == 1 && out[0] == b"") {
                    out.pop();
                }
            }
            x => out.push(x),
        });
    let out = out.join(b"/" as &[u8]);
    s.clear();
    s.add(out.as_slice());
}

//Tests
#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;
    #[rstest]
    #[case::no_port(b"http://user:pass@www.example.com:1234/path1/path2?a=b&c=d#frag",
    Some("http://user:pass@www.example.com:1234/path1/path2?a=b&c=d#frag"),
    Some("/path1/path2?a=b&c=d#frag"),
        Uri {
                cfg: DecoderConfig::default(),
                scheme: Some(Bstr::from("http")),
                username: Some(Bstr::from("user")),
                password: Some(Bstr::from("pass")),
                hostname: Some(Bstr::from("www.example.com")),
                port: Some(Bstr::from("1234")),
                port_number: None,
                path: Some(Bstr::from("/path1/path2")),
                query: Some(Bstr::from("a=b&c=d")),
                fragment: Some(Bstr::from("frag")),
        })]
    #[case::scheme_hostname_path(b"http://host.com/path",
    Some("http://host.com/path"),
    Some("/path"),
            Uri {
                cfg: DecoderConfig::default(),
                scheme: Some(Bstr::from("http")),
                username: None,
                password: None,
                hostname: Some(Bstr::from("host.com")),
                port: None,
                port_number: None,
                path: Some(Bstr::from("/path")),
                query: None,
                fragment: None,
            })]
    #[case::scheme_hostname(b"http://host.com",
    Some("http://host.com"),
    None,
            Uri {
                cfg: DecoderConfig::default(),
                scheme: Some(Bstr::from("http")),
                username: None,
                password: None,
                hostname: Some(Bstr::from("host.com")),
                port: None,
                port_number: None,
                path: None,
                query: None,
                fragment: None,
            })]
    #[case::scheme_path(b"http://",
    Some("http:////"),
    Some("//"),
            Uri {
                cfg: DecoderConfig::default(),
                scheme: Some(Bstr::from("http")),
                username: None,
                password: None,
                hostname: None,
                port: None,
                port_number: None,
                path: Some(Bstr::from("//")),
                query: None,
                fragment: None,
            })]
    #[case::path(b"/path",
    Some("/path"),
    Some("/path"),
            Uri {
                cfg: DecoderConfig::default(),
                scheme: None,
                username: None,
                password: None,
                hostname: None,
                port: None,
                port_number: None,
                path: Some(Bstr::from("/path")),
                query: None,
                fragment: None,
            })]
    #[case::empty_scheme_path(b"://",
    Some(":////"),
    Some("//"),
            Uri {
                cfg: DecoderConfig::default(),
                scheme: Some(Bstr::from("")),
                username: None,
                password: None,
                hostname: None,
                port: None,
                port_number: None,
                path: Some(Bstr::from("//")),
                query: None,
                fragment: None,
            })]
    #[case::empty(b"", None, None, Uri::default())]
    #[case::scheme_user_host(b"http://user@host.com",
    Some("http://user:@host.com"),
    None,
            Uri {
                cfg: DecoderConfig::default(),
                scheme: Some(Bstr::from("http")),
                username: Some(Bstr::from("user")),
                password: None,
                hostname: Some(Bstr::from("host.com")),
                port: None,
                port_number: None,
                path: None,
                query: None,
                fragment: None,
            })]
    fn test_parse_uri(
        #[case] input: &[u8],
        #[case] expected_normalized: Option<&str>,
        #[case] expected_partial: Option<&str>,
        #[case] expected: Uri,
    ) {
        let mut uri = Uri::default();
        uri.parse_uri(input);
        assert_eq!(uri.scheme, expected.scheme);
        assert_eq!(uri.username, expected.username);
        assert_eq!(uri.password, expected.password);
        assert_eq!(uri.hostname, expected.hostname);
        assert_eq!(uri.port, expected.port);
        assert_eq!(uri.path, expected.path);
        assert_eq!(uri.query, expected.query);
        assert_eq!(uri.fragment, expected.fragment);
        assert_eq!(
            uri.generate_normalized_uri(None),
            (
                expected_partial.map(Bstr::from),
                expected_normalized.map(Bstr::from)
            )
        );
    }

    #[rstest]
    #[case(b"/a/b/c/./../../g", b"/a/g")]
    #[case(b"mid/content=5/../6", b"mid/6")]
    #[case(b"./one", b"one")]
    #[case(b"../one", b"one")]
    #[case(b".", b"")]
    #[case(b"..", b"")]
    #[case(b"one/.", b"one")]
    #[case(b"one/..", b"")]
    #[case(b"one/../", b"")]
    #[case(b"/../../../images.gif", b"/images.gif")]
    fn test_normalize_uri_path(#[case] input: &[u8], #[case] expected: &[u8]) {
        let mut s = Bstr::from(input);
        normalize_uri_path_inplace(&mut s);
        assert!(s.eq_slice(expected))
    }
}
