extern crate proc_macro;
extern crate syn;

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    export::Span, parse_macro_input, punctuated::Punctuated, token::Brace, Block, Data,
    DeriveInput, Expr, FnArg, Ident, Item, ItemFn, Pat, ReturnType, Stmt, Token, Type,
};

fn validate_fn(item: Item) -> ItemFn {
    match item {
        Item::Fn(f) => f,
        _ => panic!("Attribute macro was not applied to a function"),
    }
}

fn wrap_args(func: &ItemFn) -> (ItemFn, Vec<(Ident, Box<Type>)>) {
    let func_clone = func.clone();
    let mut new_func = func.clone();
    let mut punc = Punctuated::<FnArg, Token!(,)>::new();
    let mut types = Vec::new();
    punc.extend(func_clone.sig.inputs.into_iter().map(|fn_arg| {
        let mut pt = match fn_arg {
            FnArg::Typed(pt) => pt,
            r => return r,
        };
        let ts = TokenStream::from(quote! {
            &str
        });
        let type_path = syn::parse::<Type>(ts).expect("Should be a valid type");
        types.push({
            let ident = match *pt.pat {
                Pat::Ident(ref idt) => idt.clone().ident,
                _ => panic!("Argument in function signature has no identifier"),
            };
            (ident, pt.ty)
        });
        pt.ty = Box::new(type_path);
        FnArg::Typed(pt)
    }));
    new_func.sig.inputs = punc;
    (new_func, types)
}

fn generate_conversions(mut new_func: ItemFn, types: Vec<(Ident, Box<Type>)>) -> ItemFn {
    let mut stmts = Vec::new();
    let conversions: Vec<Stmt> = types
        .iter()
        .map(|(ident, ty)| {
            let ts = TokenStream::from(quote! {
                let #ident = match #ident.parse::<#ty>() {
                    Ok(i) => i,
                    Err(e) => return Err(Box::new(e)),
                };
            });
            syn::parse::<Stmt>(ts).expect("Should be a valid expression")
        })
        .collect();
    stmts.extend(conversions);
    let fn_ident = new_func.sig.ident.clone();
    let args = types.iter().map(|(ident, _)| ident);
    let call_and_return: Vec<Stmt> = {
        let ts = TokenStream::from(quote! {
            let result = #fn_ident(
                #(
                    #args
                ),*
            );
        });
        let call = syn::parse::<Stmt>(ts).expect("Should be a valid statement");
        let ts = TokenStream::from(quote! {
            Ok(result)
        });
        let ret = syn::parse::<Expr>(ts).expect("Should be a valid statement");
        vec![call, Stmt::Expr(ret)]
    };
    stmts.extend(call_and_return);
    new_func.block = Box::new(Block {
        brace_token: Brace {
            span: Span::call_site(),
        },
        stmts,
    });
    new_func.sig.output = match new_func.sig.output {
        ReturnType::Type(_, ty) => {
            let ts = TokenStream::from(quote! {
                Result<#ty, Box<dyn std::error::Error>>
            });
            ReturnType::Type(
                Token!(->)(Span::call_site()),
                syn::parse::<Type>(ts)
                    .map(Box::new)
                    .expect("Should be a valid type"),
            )
        }
        ReturnType::Default => {
            let ts = TokenStream::from(quote! {
                Result<(), Box<dyn std::error::Error>>
            });
            ReturnType::Type(
                Token!(->)(Span::call_site()),
                syn::parse::<Type>(ts)
                    .map(Box::new)
                    .expect("Should be a valid type"),
            )
        }
    };
    new_func
}

#[proc_macro_attribute]
pub fn wrap_fn_args(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as Item);

    let func = validate_fn(input);
    let (mut new_func, old_types) = wrap_args(&func);

    new_func = generate_conversions(new_func, old_types);

    new_func.sig.ident = Ident::new(&format!("{}_str_input", func.sig.ident), Span::call_site());

    let expanded = quote! {
        #func

        #[cfg(feature = "macro-code")]
        #new_func
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(FromStrEnum)]
pub fn derive_from_str(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let ident = input.ident;
    let variants: Vec<Expr> = match input.data {
        Data::Enum(e) => e
            .variants
            .into_iter()
            .map(|v| {
                let var_ident = v.ident;
                let path = TokenStream::from(quote! {
                    #ident::#var_ident
                });
                syn::parse::<Expr>(path).expect("Should be valid expression")
            })
            .collect(),
        _ => panic!("Derive must be applied to an enum"),
    };
    let error_ident = Ident::new(format!("{}Error", ident).as_str(), Span::call_site());
    TokenStream::from(quote! {
        #[cfg(feature = "macro-code")]
        #[derive(Debug)]
        pub struct #error_ident(String);

        #[cfg(feature = "macro-code")]
        impl std::fmt::Display for #error_ident {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        #[cfg(feature = "macro-code")]
        impl std::error::Error for #error_ident {}

        #[cfg(feature = "macro-code")]
        impl std::str::FromStr for #ident {
            type Err = #error_ident;

            fn from_str(v: &str) -> Result<Self, Self::Err> {
                Ok(match v {
                    #(
                        v if v == stringify!(#variants).replace(' ', "") => #variants,
                    )*
                    _ => return Err(#error_ident(format!("Could not convert to type {}", stringify!(#ident)))),
                })
            }
        }
    })
}
