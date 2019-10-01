macro_rules! command_to_struct {
    ($name:tt $(, $ident:ident)*) => {
        let match s {
            $(
                stringify!($ident) => $ident,
            )*
        }
    }
}
