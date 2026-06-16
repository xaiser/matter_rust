#[cfg(test)]
#[macro_export]
macro_rules! chip_insert_faulty {
    ($expr:expr) => {
        $expr
    };
}

#[cfg(not(test))]
#[macro_export]
macro_rules! chip_insert_faulty {
    ($expr:expr) => {};
}
