//! POSIX standard type definitions.
//!
//! This module provides common POSIX types like size_t, pid_t, etc.

use crate::database::TypeDatabase;
use crate::types::*;

/// Load POSIX standard types into the database.
pub fn load_posix_types(db: &mut TypeDatabase) {
    // Basic integer typedefs (LP64 model)
    db.add_typedef("size_t", CType::ulong());
    db.add_typedef("ssize_t", CType::long());
    db.add_typedef("ptrdiff_t", CType::long());
    db.add_typedef("intptr_t", CType::long());
    db.add_typedef("uintptr_t", CType::ulong());

    // Fixed-width integer types
    db.add_typedef("int8_t", CType::Int(IntType::new(1, true)));
    db.add_typedef("uint8_t", CType::Int(IntType::new(1, false)));
    db.add_typedef("int16_t", CType::Int(IntType::new(2, true)));
    db.add_typedef("uint16_t", CType::Int(IntType::new(2, false)));
    db.add_typedef("int32_t", CType::Int(IntType::new(4, true)));
    db.add_typedef("uint32_t", CType::Int(IntType::new(4, false)));
    db.add_typedef("int64_t", CType::Int(IntType::new(8, true)));
    db.add_typedef("uint64_t", CType::Int(IntType::new(8, false)));

    // Process types
    db.add_typedef("pid_t", CType::int());
    db.add_typedef("uid_t", CType::uint());
    db.add_typedef("gid_t", CType::uint());

    // File types
    db.add_typedef("off_t", CType::long());
    db.add_typedef("mode_t", CType::uint());
    db.add_typedef("dev_t", CType::ulong());
    db.add_typedef("ino_t", CType::ulong());
    db.add_typedef("nlink_t", CType::ulong());

    // Time types
    db.add_typedef("time_t", CType::long());
    db.add_typedef("clock_t", CType::long());
    db.add_typedef("suseconds_t", CType::long());

    // Socket types
    db.add_typedef("socklen_t", CType::uint());
    db.add_typedef("sa_family_t", CType::ushort());
    db.add_typedef("in_port_t", CType::ushort());
    db.add_typedef("in_addr_t", CType::uint());

    // struct timeval
    let mut timeval = StructType::new(Some("timeval".to_string()));
    timeval.add_field("tv_sec".to_string(), CType::long());   // time_t is long on LP64
    timeval.add_field("tv_usec".to_string(), CType::long());  // suseconds_t is long on LP64
    timeval.finalize();
    db.add_type("struct timeval", CType::Struct(timeval));

    // struct timespec
    let mut timespec = StructType::new(Some("timespec".to_string()));
    timespec.add_field("tv_sec".to_string(), CType::long());  // time_t is long on LP64
    timespec.add_field("tv_nsec".to_string(), CType::long());
    timespec.finalize();
    db.add_type("struct timespec", CType::Struct(timespec));

    // struct tm (broken-down time)
    let mut tm = StructType::new(Some("tm".to_string()));
    tm.add_field("tm_sec".to_string(), CType::int());
    tm.add_field("tm_min".to_string(), CType::int());
    tm.add_field("tm_hour".to_string(), CType::int());
    tm.add_field("tm_mday".to_string(), CType::int());
    tm.add_field("tm_mon".to_string(), CType::int());
    tm.add_field("tm_year".to_string(), CType::int());
    tm.add_field("tm_wday".to_string(), CType::int());
    tm.add_field("tm_yday".to_string(), CType::int());
    tm.add_field("tm_isdst".to_string(), CType::int());
    tm.finalize();
    db.add_type("struct tm", CType::Struct(tm));

    // struct sockaddr
    let mut sockaddr = StructType::new(Some("sockaddr".to_string()));
    sockaddr.add_field("sa_family".to_string(), CType::typedef_ref("sa_family_t"));
    sockaddr.add_field("sa_data".to_string(), CType::array(CType::char(), Some(14)));
    sockaddr.finalize();
    db.add_type("struct sockaddr", CType::Struct(sockaddr));

    // struct in_addr
    let mut in_addr = StructType::new(Some("in_addr".to_string()));
    in_addr.add_field("s_addr".to_string(), CType::typedef_ref("in_addr_t"));
    in_addr.finalize();
    db.add_type("struct in_addr", CType::Struct(in_addr.clone()));

    // struct sockaddr_in
    let mut sockaddr_in = StructType::new(Some("sockaddr_in".to_string()));
    sockaddr_in.add_field("sin_family".to_string(), CType::typedef_ref("sa_family_t"));
    sockaddr_in.add_field("sin_port".to_string(), CType::typedef_ref("in_port_t"));
    sockaddr_in.add_field("sin_addr".to_string(), CType::Struct(in_addr));
    sockaddr_in.add_field("sin_zero".to_string(), CType::array(CType::char(), Some(8)));
    sockaddr_in.finalize();
    db.add_type("struct sockaddr_in", CType::Struct(sockaddr_in));

    // struct iovec (scatter/gather I/O)
    let mut iovec = StructType::new(Some("iovec".to_string()));
    iovec.add_field("iov_base".to_string(), CType::ptr(CType::void()));
    iovec.add_field("iov_len".to_string(), CType::typedef_ref("size_t"));
    iovec.finalize();
    db.add_type("struct iovec", CType::Struct(iovec));

    // struct pollfd
    let mut pollfd = StructType::new(Some("pollfd".to_string()));
    pollfd.add_field("fd".to_string(), CType::int());
    pollfd.add_field("events".to_string(), CType::short());
    pollfd.add_field("revents".to_string(), CType::short());
    pollfd.finalize();
    db.add_type("struct pollfd", CType::Struct(pollfd));

    // FILE* is an opaque pointer
    db.add_typedef("FILE", CType::Named("struct _IO_FILE".to_string()));

    // DIR* is an opaque pointer
    db.add_typedef("DIR", CType::Named("struct __dirstream".to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_posix_types() {
        let mut db = TypeDatabase::new();
        load_posix_types(&mut db);

        assert!(db.has_type("size_t"));
        assert!(db.has_type("pid_t"));
        assert!(db.has_type("struct timeval"));
        assert!(db.has_type("struct sockaddr"));
    }

    #[test]
    fn test_struct_timeval() {
        let mut db = TypeDatabase::new();
        load_posix_types(&mut db);

        let field = db.format_field_access("struct timeval", 0);
        assert_eq!(field, Some(".tv_sec".to_string()));

        let field = db.format_field_access("struct timeval", 8);
        assert_eq!(field, Some(".tv_usec".to_string()));
    }
}
