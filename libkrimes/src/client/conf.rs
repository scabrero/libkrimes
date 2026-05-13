use pest::Parser;
use pest_derive::Parser;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, error};

#[derive(Parser)]
#[grammar = "client/krb5.pest"]
pub struct KerberosConfigParser;

#[derive(Debug)]
pub enum KerberosConfigError {
    IoError(std::io::Error),
    ParseError(pest::error::Error<Rule>),
    Dummy,
}

#[derive(Debug, PartialEq)]
pub struct KerberosConfig {
    pub sections: HashMap<String, Section>,
}

type Final = bool;

#[derive(Debug, PartialEq)]
pub struct Section {
    pub name: String,
    pub relations: HashMap<String, (Final, Value)>,
}

#[derive(Debug, PartialEq)]
pub enum Value {
    // Last value is the latest read
    String(Vec<String>),
    Section(Section),
}

impl KerberosConfig {
    /// Parse the content of a `krb5.conf` file from a &str
    pub fn parse(input: &str) -> Result<KerberosConfig, KerberosConfigError> {
        let parsed = KerberosConfigParser::parse(Rule::file, input)
            .map_err(KerberosConfigError::ParseError)?
            .next()
            .ok_or(KerberosConfigError::Dummy)?;
        println!("{:#?}", parsed);

        let mut config = KerberosConfig {
            sections: HashMap::new(),
        };

        for record in parsed.into_inner() {
            match record.as_rule() {
                Rule::section => {
                    let mut section_name = String::new();
                    let mut relations = HashMap::new();

                    for section_part in record.into_inner() {
                        match section_part.as_rule() {
                            Rule::section_name => section_name = section_part.as_str().to_string(),
                            Rule::relation => {
                                let mut relation_parts = section_part.into_inner();
                                let tag = relation_parts.next().expect("TODO").as_str().to_string();
                                let value_part = relation_parts.next().expect("TODO");
                                let value = match value_part.as_rule() {
                                    Rule::value => {
                                        Value::String(vec![value_part.as_str().to_string()])
                                    }
                                    Rule::relation => {
                                        todo!()
                                    }
                                    _ => unreachable!(),
                                };
                                relations.insert(tag, (false, value));
                            }
                            Rule::final_mark => {
                                todo!()
                            }
                            _ => {
                                unreachable!()
                            }
                        }
                    }
                    config.sections.insert(
                        section_name.clone(),
                        Section {
                            name: section_name,
                            relations,
                        },
                    );
                }
                Rule::comment => {}
                Rule::include_file => {
                    todo!()
                }
                Rule::include_dir => {
                    todo!()
                }
                Rule::EOI => {}
                x => {
                    error!("Unhandled rule {:#?}", x);
                    unreachable!();
                }
            }
        }

        Ok(config)
    }

    pub fn from_file(path: Option<PathBuf>) -> Result<(), KerberosConfigError> {
        let path = match path {
            Some(p) => p,
            None => match env::var("KRB5_CONFIG") {
                Ok(v) => PathBuf::from(v),
                Err(_) => return Err(KerberosConfigError::Dummy), //Self::from_usr_etc_merge(),
            },
        };
        let unparsed = fs::read_to_string(path.as_path()).map_err(|e| {
            debug!("Failed to read file {path:?}: {e}");
            KerberosConfigError::IoError(e)
        })?;

        let _parsed = KerberosConfigParser::parse(Rule::file, &unparsed).map_err(|e| {
            error!("Failed to parse file {path:?}: {e}");
            KerberosConfigError::ParseError(e)
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    //    use std::fs::File;
    //    use std::io::Write;
    //    use tempfile::tempdir;
    //    use tempfile::NamedTempFile;

    #[test]
    fn test_config_basic_section_parsing() {
        let input = r#"
            [libdefaults]
            default_realm = EXAMPLE.COM
            ticket_lifetime = 24h
        "#;

        let result = KerberosConfig::parse(input);
        assert!(result.is_ok());

        let config = result.unwrap();
        println!("Parsed: {:#?}", config);
        assert!(config.sections.contains_key("libdefaults"));

        let libdefaults = &config.sections["libdefaults"];
        assert_eq!(
            libdefaults.relations.get("default_realm"),
            Some(&(false, Value::String(vec!["EXAMPLE.COM".to_string()])))
        );
        assert_eq!(
            libdefaults.relations.get("ticket_lifetime"),
            Some(&(false, Value::String(vec!["24h".to_string()])))
        );
    }

    //    #[test]
    //    fn test_non_closed_nested_section_parsing() {
    //        // Test non-closed subsections
    //        let input = r#"
    //            [realms]
    //                EXAMPLE.COM = {
    //                    kdc = kerberos.example.com
    //                    admin_server = admin.example.com
    //            "#;
    //
    //        let result = Krb5Config::parse(input);
    //        assert!(result.is_err());
    //    }
    //
    //    #[test]
    //    fn test_nested_section_parsing() {
    //        let input = r#"
    //            [realms]
    //                EXAMPLE.COM = {
    //                    kdc = kerberos.example.com
    //                    admin_server = admin.example.com
    //                }
    //            "#;
    //
    //        let result = Krb5Config::parse(input);
    //        assert!(result.is_ok());
    //
    //        let config = result.unwrap();
    //        assert!(config.sections.contains_key("realms"));
    //
    //        let realms = &config.sections["realms"];
    //        let realm_entry = realms.get("EXAMPLE.COM");
    //        assert!(realm_entry.is_some());
    //
    //        if let Krb5Value::Section(nested_section) = realm_entry.unwrap() {
    //            assert_eq!(
    //                nested_section.get("kdc"),
    //                Some(&Krb5Value::String("kerberos.example.com".to_string()))
    //            );
    //            assert_eq!(
    //                nested_section.get("admin_server"),
    //                Some(&Krb5Value::String("admin.example.com".to_string()))
    //            );
    //        } else {
    //            panic!("Expected nested section, but got something else");
    //        }
    //
    //        // Test nested recursion
    //        let input = r#"
    //          [appdefaults]
    //              telnet = {
    //                  ATHENA.MIT.EDU = {
    //                      option1 = false
    //                  }
    //              }
    //              telnet = {
    //                  option1 = true
    //                  option2 = true
    //              }
    //              ATHENA.MIT.EDU = {
    //                  option2 = false
    //              }
    //              option2 = true
    //        "#;
    //
    //        let result = Krb5Config::parse(input);
    //        assert!(result.is_ok());
    //
    //        // From krb5.conf manpage:
    //        //
    //        // if telnet is running in the realm EXAMPLE.COM, it should, by default, have option1 and option2 set to true.
    //        // However, a telnet program in the realm ATHENA.MIT.EDU should have option1 set to false and option2 set to
    //        // true. Any other programs in ATHENA.MIT.EDU should have option2 set to false by default.  Any programs
    //        // running in other realms should have option2 set to true.
    //
    //        let config = result.unwrap();
    //        let appdefaults = config.sections.get("appdefaults").expect("appdefaults");
    //
    //        if let Krb5Value::Section(telnet) = appdefaults.get("telnet").expect("telnet") {
    //            assert_eq!(telnet.len(), 3);
    //
    //            assert_eq!(
    //                telnet.get("option1"),
    //                Some(&Krb5Value::String("true".to_string()))
    //            );
    //            assert_eq!(
    //                telnet.get("option2"),
    //                Some(&Krb5Value::String("true".to_string()))
    //            );
    //
    //            if let Krb5Value::Section(athena) = telnet
    //                .get("ATHENA.MIT.EDU")
    //                .expect("ATHENA.MIT.EDU specific options")
    //            {
    //                assert_eq!(athena.len(), 1);
    //                assert_eq!(
    //                    athena.get("option1"),
    //                    Some(&Krb5Value::String("false".to_string()))
    //                );
    //            }
    //        }
    //
    //        if let Krb5Value::Section(athena) = appdefaults
    //            .get("ATHENA.MIT.EDU")
    //            .expect("ATHENA.MIT.EDU options for all apps")
    //        {
    //            assert_eq!(
    //                athena.get("option2"),
    //                Some(&Krb5Value::String("false".to_string()))
    //            );
    //        }
    //
    //        assert_eq!(
    //            appdefaults.get("option2"),
    //            Some(&Krb5Value::String("true".to_string()))
    //        );
    //    }
    //
    //    #[test]
    //    fn test_comments_and_whitespace() {
    //        let input = r#"
    //            # This is a comment
    //            [libdefaults]
    //            default_realm = EXAMPLE.COM
    //
    //            ; Another comment format
    //              ; This time with leading spaces
    //               # in both formats
    //            ticket_lifetime = 24h
    //        "#;
    //
    //        let result = Krb5Config::parse(input);
    //        assert!(result.is_ok());
    //
    //        let config = result.unwrap();
    //        assert!(config.sections.contains_key("libdefaults"));
    //
    //        let libdefaults = &config.sections["libdefaults"];
    //        assert_eq!(
    //            libdefaults.get("default_realm"),
    //            Some(&Krb5Value::String("EXAMPLE.COM".to_string()))
    //        );
    //        assert_eq!(
    //            libdefaults.get("ticket_lifetime"),
    //            Some(&Krb5Value::String("24h".to_string()))
    //        );
    //        assert_eq!(libdefaults.len(), 2);
    //    }
    //
    //    #[test]
    //    fn test_invalid_line() {
    //        let input = r#"
    //            [libdefaults]
    //            # Missing '='
    //            default_realm EXAMPLE.COM
    //        "#;
    //
    //        let result = Krb5Config::parse(input);
    //        assert!(result.is_err());
    //
    //        let error_message = result.unwrap_err();
    //        assert!(error_message.contains("Invalid line"));
    //    }
    //
    //    #[test]
    //    fn test_empty_config() {
    //        let input = "";
    //
    //        let result = Krb5Config::parse(input);
    //        assert!(result.is_ok());
    //
    //        let config = result.unwrap();
    //        assert!(config.sections.is_empty());
    //    }
    //
    //    #[test]
    //    fn test_from_file_success() {
    //        let file_content = r#"
    //            [domain_realm]
    //            .example.com = EXAMPLE.COM
    //            .otherdomain.com = OTHERREALM.COM
    //        "#;
    //
    //        // Write test content to a temporary file
    //        let mut file = NamedTempFile::new().expect("new namedtempfile");
    //        file.write_all(file_content.as_bytes())
    //            .expect("Failed to write to temporary file");
    //        file.flush().expect("flush temp file");
    //
    //        // Test from_file
    //        let result = Krb5Config::from_file(Some(file.path()));
    //        assert!(result.is_ok());
    //
    //        let config = result.unwrap();
    //        assert!(config.sections.contains_key("domain_realm"));
    //
    //        let domain_realm = &config.sections["domain_realm"];
    //        assert_eq!(
    //            domain_realm.get(".example.com"),
    //            Some(&Krb5Value::String("EXAMPLE.COM".to_string()))
    //        );
    //        assert_eq!(
    //            domain_realm.get(".otherdomain.com"),
    //            Some(&Krb5Value::String("OTHERREALM.COM".to_string()))
    //        );
    //
    //        // Clean up temporary file
    //        file.close().expect("close temp file");
    //    }
    //
    //    #[test]
    //    fn test_from_file_failure() {
    //        let invalid_path = std::path::Path::new("non_existent.conf");
    //        let result = Krb5Config::from_file(Some(invalid_path));
    //        assert!(result.is_err());
    //    }
    //
    //    #[test]
    //    fn test_parse_include() {
    //        let content = r#"
    //            [libdefaults]
    //            default_realm = FROM.INCLUDED.CONF
    //        "#;
    //        let mut inc_file = NamedTempFile::new().expect("new namedtempfile");
    //        inc_file
    //            .write_all(content.as_bytes())
    //            .expect("Failed to write to temporary file");
    //        inc_file.flush().expect("flush temp file");
    //
    //        let content = r#"
    //            [libdefaults]
    //            default_realm = FROM.MAIN.CONF
    //        "#;
    //        let content = format!("include {}\n{}", inc_file.path().to_string_lossy(), content);
    //        let mut main_file = NamedTempFile::new().expect("new namedtempfile");
    //        main_file
    //            .write_all(content.as_bytes())
    //            .expect("Failed to write to temporary file");
    //        main_file.flush().expect("flush temp file");
    //
    //        let config = Krb5Config::from_file(Some(main_file.path())).expect("parse");
    //
    //        let libdefaults = config.sections.get("libdefaults").expect("libdefaults");
    //        assert_eq!(
    //            libdefaults.get("default_realm"),
    //            Some(&Krb5Value::String("FROM.INCLUDED.CONF".to_string()))
    //        );
    //
    //        main_file.close().expect("close");
    //        inc_file.close().expect("close");
    //    }
    //
    //    #[test]
    //    fn test_parse_includedir() {
    //        let inc_dir = tempdir().expect("tempdir");
    //
    //        let inc_a_content = r#"
    //            [libdefaults]
    //            default_realm = FROM.INC.A.CONF
    //        "#;
    //
    //        let inc_b_content = r#"
    //            [libdefaults]
    //            default_realm = FROM.INC.B.CONF
    //        "#;
    //
    //        let inc_a_path = inc_dir.path().join("a.conf");
    //        let mut inc_a_file = File::create(inc_a_path).expect("create");
    //        inc_a_file
    //            .write_all(inc_a_content.as_bytes())
    //            .expect("Failed to write to temporary file");
    //        inc_a_file.flush().expect("flush temp file");
    //
    //        let inc_b_path = inc_dir.path().join("b.conf");
    //        let mut inc_b_file = File::create(inc_b_path).expect("create");
    //        inc_b_file
    //            .write_all(inc_b_content.as_bytes())
    //            .expect("Failed to write to temporary file");
    //        inc_b_file.flush().expect("flush temp file");
    //
    //        let main_content = format!(
    //            "
    //            includedir {}
    //            [libdefaults]
    //            default_realm = FROM.MAIN.CONF
    //        ",
    //            inc_dir.path().to_string_lossy()
    //        );
    //        let mut main_file = NamedTempFile::new().expect("new namedtempfile");
    //        main_file
    //            .write_all(main_content.as_bytes())
    //            .expect("Failed to write to temporary file");
    //        main_file.flush().expect("flush temp file");
    //
    //        let config = Krb5Config::from_file(Some(main_file.path())).expect("parse");
    //
    //        let libdefaults = config.sections.get("libdefaults").expect("libdefaults");
    //        assert_eq!(
    //            libdefaults.get("default_realm"),
    //            Some(&Krb5Value::String("FROM.INC.B.CONF".to_string()))
    //        );
    //
    //        drop(inc_a_file);
    //        drop(inc_b_file);
    //        inc_dir.close().expect("close");
    //        main_file.close().expect("close");
    //    }
}
