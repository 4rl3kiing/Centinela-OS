//! Memory permission policy shared by paging and executable-loading code.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagePermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub user_accessible: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionError {
    WriteExecuteViolation,
}

impl PagePermissions {
    /// Construct permissions while enforcing the W^X invariant.
    pub const fn new(
        readable: bool,
        writable: bool,
        executable: bool,
        user_accessible: bool,
    ) -> Result<Self, PermissionError> {
        if writable && executable {
            return Err(PermissionError::WriteExecuteViolation);
        }

        Ok(Self {
            readable,
            writable,
            executable,
            user_accessible,
        })
    }

    pub const fn is_write_xor_execute(self) -> bool {
        !(self.writable && self.executable)
    }
}

#[cfg(test)]
mod tests {
    use super::{PagePermissions, PermissionError};

    #[test]
    fn rejects_writable_executable_pages() {
        assert_eq!(
            PagePermissions::new(true, true, true, false),
            Err(PermissionError::WriteExecuteViolation)
        );
    }

    #[test]
    fn accepts_read_write_non_executable_pages() {
        let permissions = PagePermissions::new(true, true, false, true)
            .expect("RW/NX permissions must be accepted");
        assert!(permissions.is_write_xor_execute());
    }
}
