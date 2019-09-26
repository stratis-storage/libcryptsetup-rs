#[macro_use]
extern crate cryptsetup_cli_proc_macro;
extern crate proc_macro;

use cryptsetup_cli_proc_macro::wrap_fn_args;

#[test]
fn test_function_wrapped() {
    #[derive(FromStrEnum, Debug, PartialEq)]
    enum Test {
        TestOne,
        TestTwo,
        TestThree,
    }

    #[wrap_fn_args]
    fn test_function(
        one: u8,
        two: u16,
        three: u32,
        four: String,
        five: Test,
    ) -> (u64, String, Test) {
        (one as u64 + two as u64 + three as u64, four, five)
    }

    assert_eq!(
        test_function_str_input("1", "2", "3", "Test string", "Test::TestOne").unwrap(),
        (6, "Test string".to_string(), Test::TestOne)
    );
}
