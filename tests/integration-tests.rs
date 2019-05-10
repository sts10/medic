mod integration_tests {
    use entries::build_entries_from_keepass_db;
    use entries::Entry;
    use medic::*;
    use std::path::PathBuf;

    fn make_test_entries_from_keepass_database_requiring_keyfile() -> Vec<Entry> {
        let keepass_db_file_path = PathBuf::from("tests/test-files/test_db.kdbx");
        let test_db_pass = "password".to_string();
        let test_keyfile = Some(PathBuf::from("tests/test-files/test_key_file"));
        build_entries_from_keepass_db(keepass_db_file_path, test_db_pass, test_keyfile)
    }

    #[test]
    fn can_check_keepass_db_against_haveibeenpwned_api_online() {
        let entries = make_test_entries_from_keepass_database_requiring_keyfile();
        let breached_entries = check_database_online(&entries);
        assert_eq!(breached_entries.len(), 3);
    }

    // you're going to want to run this test by running `cargo test --release`, else it's going to take
    // a real long time
    #[test]
    fn can_check_keepass_db_against_offline_list_of_hashes() {
        let entries = make_test_entries_from_keepass_database_requiring_keyfile();
        let hash_file = PathBuf::from("../hibp/pwned-passwords-sha1-ordered-by-count-v4.txt");

        let breached_entries =
            check_database_offline(hash_file, &entries, VisibilityPreference::Hide).unwrap();
        assert_eq!(breached_entries.len(), 3);
    }

    #[test]
    fn can_make_a_digest_map_from_keepass_database() {
        let entries = make_test_entries_from_keepass_database_requiring_keyfile();

        let digest_map = make_digest_map(&entries).unwrap();

        let mut number_of_entries_with_duplicate_passwords = 0;
        for groups in digest_map.values() {
            if groups.len() > 1 {
                for _entry in groups {
                    number_of_entries_with_duplicate_passwords += 1;
                }
            }
        }

        assert_eq!(number_of_entries_with_duplicate_passwords, 2);
    }

    // #######################################################################
    // # Some tests using a KeePass database that does NOT require a keyfile #
    // #######################################################################

    fn make_test_entries_from_keepass_database_not_requiring_keyfile() -> Vec<Entry> {
        let keepass_db_file_path = PathBuf::from("tests/test-files/test_db_no_keyfile.kdbx");
        let test_db_pass = "password".to_string();
        build_entries_from_keepass_db(keepass_db_file_path, test_db_pass, None)
    }

    #[test]
    fn can_check_keepass_db_that_does_not_require_a_keyfile_against_haveibeenpwned_api_online() {
        let entries = make_test_entries_from_keepass_database_not_requiring_keyfile();
        let breached_entries = check_database_online(&entries);
        assert_eq!(breached_entries.len(), 3);
    }

    #[test]
    fn can_make_a_digest_map_from_keepass_database_that_does_not_require_a_keyfile() {
        let entries = make_test_entries_from_keepass_database_not_requiring_keyfile();

        let digest_map = make_digest_map(&entries).unwrap();

        let mut number_of_entries_with_duplicate_passwords = 0;
        for groups in digest_map.values() {
            if groups.len() > 1 {
                for _entry in groups {
                    number_of_entries_with_duplicate_passwords += 1;
                }
            }
        }

        assert_eq!(number_of_entries_with_duplicate_passwords, 2);
    }
}
