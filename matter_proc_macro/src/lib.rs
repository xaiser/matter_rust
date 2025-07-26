use proc_macro::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{parse_macro_input, DeriveInput};

/*
 * This macro will inerst the init impl for each field. Fro example:
 * #[derive(Init)]
 * struct Tu<T> {
 *     m_transport: (TypeA, TypeB),
 *     m_a: u32,
 *     m_b: (bool, i32),
 *  }
 *
 *  Result:
 * impl<T> Tu<T> {
 * pub fn init(
 * &mut self,
 * p0_0: <TypeA as Initializable>::Param,
 * p0_1: <TypeB as Initializable>::Param,
 * p1: u32,
 * p2_0: bool,
 * p2_1: i32,
 * ) {
 * self.m_transport.0.init(p0_0);
 * self.m_transport.1.init(p0_1);
 * self.m_a = p1;
 * self.m_b.0 = p2_0;
 * self.m_b.1 = p2_1;
 * }
 * }
*/

#[proc_macro_derive(TupleInit)]
pub fn tuple_init_macro(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;

    let fields = if let syn::Data::Struct(s) = input.data {
        s.fields
    } else {
        panic!("Init can only be derived for structs");
    };

    let mut param_defs = Vec::new();
    let mut init_calls = Vec::new();
    for (field_idx, field) in fields.iter().enumerate() {
        let field_name = field.ident.as_ref().map(|f| quote! { #f });
        let ty = &field.ty;

        match ty {
            syn::Type::Tuple(tuple) => {
                for (idx, elem) in tuple.elems.iter().enumerate() {
                    let param_name =
                        syn::Ident::new(&format!("p{}_{}", field_idx, idx), field.ty.span());
                    param_defs
                        .push(quote! { #param_name: <#elem as super::base::Init>::InitParamType });

                    if let Some(field_name) = &field_name {
                        init_calls.push(quote! { self.#field_name.#idx.init(#param_name); });
                    } else {
                        init_calls.push(quote! { self.#field_idx.#idx.init(#param_name); });
                    }
                }
            }
            _ => {
                let param_name = syn::Ident::new(&format!("p{}", field_idx), field.ty.span());
                param_defs.push(quote! { #param_name: #ty });

                if let Some(field_name) = &field_name {
                    init_calls.push(quote! { self.#field_name = #param_name; });
                } else {
                    init_calls.push(quote! { self.#field_idx = #param_name; });
                }
            }
        }
    }

    let expanded = quote! {
        impl #struct_name {
            pub fn init(&mut self, #(#param_defs),*) {
                #(#init_calls)*
            }
        }
    };

    TokenStream::from(expanded)
}
