#[derive(Debug, PartialEq)]
pub struct BasicConstraints {
    pub ca : bool,
    pub path_len_contraint: Option<u32>,
}
