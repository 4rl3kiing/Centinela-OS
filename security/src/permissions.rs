//! Memory permission policy shared by paging and executable-loading code.

/// Validated page permissions.
///
/// Fields are private so the W^X invariant cannot be bypassed with a struct
/// literal: the only constructor is [`PagePermissions::new`], which rejects
/// writable+executable combinations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagePermissions {
    readable: bool,
    writable: bool,
    executable: bool,
    user_accessible: bool,
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

    pub const fn readable(self) -> bool {
        self.readable
    }

    pub const fn writable(self) -> bool {
        self.writable
    }

    pub const fn executable(self) -> bool {
        self.executable
    }

    pub const fn user_accessible(self) -> bool {
        self.user_accessible
    }

    /// Always true for values of this type; kept as an explicit audit hook.
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

#[cfg(kani)]
mod verification {
    use super::{PagePermissions, PermissionError};

    #[kani::proof]
    fn page_permissions_never_accept_write_and_execute_together() {
        let readable: bool = kani::any();
        let writable: bool = kani::any();
        let executable: bool = kani::any();
        let user_accessible: bool = kani::any();

        let result = PagePermissions::new(readable, writable, executable, user_accessible);
        assert_eq!(result.is_ok(), !(writable && executable));
        match result {
            Ok(permissions) => assert!(permissions.is_write_xor_execute()),
            Err(error) => {
                assert_eq!(error, PermissionError::WriteExecuteViolation);
                assert!(writable && executable);
            }
        }
    }
}
