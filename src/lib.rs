pub mod rayon_wrapper {
    pub use rayon::iter::{IntoParallelIterator, ParallelIterator};
}

pub use rayon_wrapper::*;

#[doc(hidden)]
#[macro_export]
pub fn __requires_sendable_closure<R, F: FnOnce() -> R + Send>(x: F) -> F {
    x
}

#[doc(hidden)]
#[macro_export]
macro_rules! __join_implementation {
    ($len:expr; $($f:ident $r:ident $a:expr),*; $b:expr, $($c:expr,)*) => {
        $crate::__join_implementation!{$len + 1; $($f $r $a,)* f r $b; $($c,)* }
    };
    ($len:expr; $($f:ident $r:ident $a:expr),* ;) => {
        match ($(Some($crate::__requires_sendable_closure($a)),)*) {
            ($(mut $f,)*) => {
                $(let mut $r = None;)*
                let array: [&mut (dyn FnMut() + Send); $len] = [
                    $(&mut || $r = Some((&mut $f).take().unwrap()())),*
                ];
                $crate::rayon_wrapper::ParallelIterator::for_each(
                    $crate::rayon_wrapper::IntoParallelIterator::into_par_iter(array),
                    |f| f(),
                );
                ($($r.unwrap(),)*)
            }
        }
    };
}

#[macro_export]
macro_rules! join {
    ($($($a:expr),+$(,)?)?) => {
        $crate::__join_implementation!{0;;$($($a,)+)?}
    };
}