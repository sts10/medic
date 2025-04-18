mod integration_tests {
    use entries::Entry;
    use entries::build_entries_from_keepass_db;
    use medic::*;
    use std::path::PathBuf;

    // KeePass db version 4.0 test(s)

    fn make_test_entries_from_keepass_4_database_requiring_keyfile() -> Vec<Entry> {
        let keepass_db_file_path = PathBuf::from("tests/test-files/v4/version_4_test_db.kdbx");
        let test_db_pass = "password".to_string();
        let test_keyfile = Some(PathBuf::from(
            "tests/test-files/v4/version_4_test_db_keyfile",
        ));
        build_entries_from_keepass_db(keepass_db_file_path, test_db_pass, test_keyfile).unwrap()
    }

    #[test]
    fn can_make_a_digest_map_from_keepass_database_and_find_duplicate_passwords() {
        let entries = make_test_entries_from_keepass_4_database_requiring_keyfile();
        let digest_map = make_digest_map(&entries).unwrap();

        let mut number_of_entries_with_duplicate_passwords = 0;
        for groups in digest_map.values() {
            if groups.len() > 1 {
                for _entry in groups {
                    number_of_entries_with_duplicate_passwords += 1;
                }
            }
        }

        assert_eq!(number_of_entries_with_duplicate_passwords, 4);
    }

    #[test]
    fn can_check_keepass_db_against_haveibeenpwned_api_online() {
        let entries: Vec<Entry> = make_test_entries_from_keepass_4_database_requiring_keyfile();
        let breached_entries = check_database_online(&entries);
        assert_eq!(breached_entries.unwrap().len(), 3);
    }

    #[test]
    fn can_check_keepass_db_against_small_offline_list_of_cleartext_passwords() {
        let entries = make_test_entries_from_keepass_4_database_requiring_keyfile();
        let passwords_file = PathBuf::from("tests/test-files/cleartext_passwords.txt");

        let breached_entries = check_database_offline(
            passwords_file,
            &entries,
            &VisibilityPreference::Hide,
            BreachedPasswordState::Clear,
        )
        .unwrap();
        assert_eq!(breached_entries.len(), 4);
    }

    #[test]
    fn can_check_keepass_db_against_small_offline_list_of_hashes() {
        let entries = make_test_entries_from_keepass_4_database_requiring_keyfile();
        let hash_file = PathBuf::from("tests/test-files/abbreviated_hibp_hashes.txt");

        let breached_entries = check_database_offline(
            hash_file,
            &entries,
            &VisibilityPreference::Hide,
            BreachedPasswordState::Sha1,
        )
        .unwrap();
        assert_eq!(breached_entries.len(), 3);
    }
    // The test below checks a test KeePass db against an externally provided hash file at
    // "tests/test-files/abbreviated_hibp_hashes.txt"
    // Which can be the full HaveIBeenPwned Password file (available at
    // https://haveibeenpwned.com/Passwords
    // The test is `ignore`d by default since (a) devs need to have the HIBP file available
    // locally and (b) it takes a long time (recommend you run `cargo test --release`)
    #[test]
    #[ignore]
    fn can_check_keepass_db_against_full_haveibeenpwned_local_list_of_hashes() {
        let entries = make_test_entries_from_keepass_4_database_requiring_keyfile();
        let hash_file = PathBuf::from("../hibp/pwned-passwords-sha1-ordered-by-count-v8.txt");

        let breached_entries = check_database_offline(
            hash_file,
            &entries,
            &VisibilityPreference::Hide,
            BreachedPasswordState::Sha1,
        )
        .unwrap();
        assert_eq!(breached_entries.len(), 3);
    }

    // Some tests using a KeePass v4.0 database that does NOT require a keyfile

    fn make_test_entries_from_keepass_database_not_requiring_keyfile() -> Vec<Entry> {
        let keepass_db_file_path = PathBuf::from("tests/test-files/v4/test_db_no_keyfile_v4.kdbx");
        let test_db_pass = "password".to_string();
        build_entries_from_keepass_db(keepass_db_file_path, test_db_pass, None).unwrap()
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
    #[test]
    fn can_check_keepass_db_that_does_not_require_a_keyfile_against_haveibeenpwned_api_online() {
        let entries = make_test_entries_from_keepass_database_not_requiring_keyfile();
        let breached_entries = check_database_online(&entries);
        assert_eq!(breached_entries.unwrap().len(), 3);
    }

    // Test reading and checking "legacy" KeePass file format (v3.1)

    fn make_test_entries_from_keepass_database_3_1_requiring_keyfile() -> Vec<Entry> {
        let keepass_db_file_path = PathBuf::from("tests/test-files/v3_1/test_db.kdbx");
        let test_db_pass = "password".to_string();
        let test_keyfile = Some(PathBuf::from("tests/test-files/v3_1/test_key_file"));
        build_entries_from_keepass_db(keepass_db_file_path, test_db_pass, test_keyfile).unwrap()
    }

    #[test]
    fn can_check_keepass_v3_1_db_that_requires_a_keyfile_against_haveibeenpwned_api_online() {
        let entries = make_test_entries_from_keepass_database_3_1_requiring_keyfile();
        let breached_entries = check_database_online(&entries);
        assert_eq!(breached_entries.unwrap().len(), 3);
    }

    fn make_test_entries_from_keepass_database_3_1_not_requiring_keyfile() -> Vec<Entry> {
        let keepass_db_file_path = PathBuf::from("tests/test-files/v3_1/test_db_no_keyfile.kdbx");
        let test_db_pass = "password".to_string();
        build_entries_from_keepass_db(keepass_db_file_path, test_db_pass, None).unwrap()
    }

    // I believe this test results in an infinite loop due to an issue in version 0.4.4 of the
    // keepass-rs crate dependency
    #[test]
    fn can_check_keepass_v3_1_db_that_does_not_require_a_keyfile_against_haveibeenpwned_api_online()
    {
        let entries = make_test_entries_from_keepass_database_3_1_not_requiring_keyfile();
        let breached_entries = check_database_online(&entries);
        assert_eq!(breached_entries.unwrap().len(), 3);
    }

    // Test reading a CSV file (exported KeePass database)
    fn make_test_entries_from_csv_export() -> Option<Vec<Entry>> {
        let keepass_db_file_path = PathBuf::from("tests/test-files/csv_exports/csv_export.csv");
        get_entries(keepass_db_file_path, None)
    }

    #[test]
    fn can_check_csv_export() {
        let entries = make_test_entries_from_csv_export().unwrap();
        let breached_entries = check_database_online(&entries);
        assert_eq!(breached_entries.unwrap().len(), 3); // there are 3 breached passwords in this test file
    }
}
