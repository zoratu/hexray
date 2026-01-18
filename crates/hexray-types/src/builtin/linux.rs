//! Linux-specific type definitions.
//!
//! This module provides Linux-specific types like struct stat, etc.

use crate::database::TypeDatabase;
use crate::types::*;

/// Load Linux-specific types into the database.
pub fn load_linux_types(db: &mut TypeDatabase) {
    // struct stat (x86_64 Linux) - using concrete types for correct offsets
    let mut stat = StructType::new(Some("stat".to_string()));
    stat.add_field("st_dev".to_string(), CType::ulong());      // dev_t - offset 0
    stat.add_field("st_ino".to_string(), CType::ulong());      // ino_t - offset 8
    stat.add_field("st_nlink".to_string(), CType::ulong());    // nlink_t - offset 16
    stat.add_field("st_mode".to_string(), CType::uint());      // mode_t - offset 24
    stat.add_field("st_uid".to_string(), CType::uint());       // uid_t - offset 28
    stat.add_field("st_gid".to_string(), CType::uint());       // gid_t - offset 32
    stat.add_field("__pad0".to_string(), CType::int());        // offset 36
    stat.add_field("st_rdev".to_string(), CType::ulong());     // dev_t - offset 40
    stat.add_field("st_size".to_string(), CType::long());      // off_t - offset 48
    stat.add_field("st_blksize".to_string(), CType::long());   // offset 56
    stat.add_field("st_blocks".to_string(), CType::long());    // offset 64
    // struct timespec is 16 bytes (8 + 8)
    stat.add_field("st_atim_sec".to_string(), CType::long());  // offset 72
    stat.add_field("st_atim_nsec".to_string(), CType::long()); // offset 80
    stat.add_field("st_mtim_sec".to_string(), CType::long());  // offset 88
    stat.add_field("st_mtim_nsec".to_string(), CType::long()); // offset 96
    stat.add_field("st_ctim_sec".to_string(), CType::long());  // offset 104
    stat.add_field("st_ctim_nsec".to_string(), CType::long()); // offset 112
    stat.add_field("__unused".to_string(), CType::array(CType::long(), Some(3))); // offset 120
    stat.finalize();
    db.add_type("struct stat", CType::Struct(stat));

    // struct dirent
    let mut dirent = StructType::new(Some("dirent".to_string()));
    dirent.add_field("d_ino".to_string(), CType::typedef_ref("ino_t"));
    dirent.add_field("d_off".to_string(), CType::typedef_ref("off_t"));
    dirent.add_field("d_reclen".to_string(), CType::ushort());
    dirent.add_field("d_type".to_string(), CType::uchar());
    dirent.add_field("d_name".to_string(), CType::array(CType::char(), Some(256)));
    dirent.finalize();
    db.add_type("struct dirent", CType::Struct(dirent));

    // struct rusage
    let mut rusage = StructType::new(Some("rusage".to_string()));
    rusage.add_field("ru_utime".to_string(), CType::Named("struct timeval".to_string()));
    rusage.add_field("ru_stime".to_string(), CType::Named("struct timeval".to_string()));
    rusage.add_field("ru_maxrss".to_string(), CType::long());
    rusage.add_field("ru_ixrss".to_string(), CType::long());
    rusage.add_field("ru_idrss".to_string(), CType::long());
    rusage.add_field("ru_isrss".to_string(), CType::long());
    rusage.add_field("ru_minflt".to_string(), CType::long());
    rusage.add_field("ru_majflt".to_string(), CType::long());
    rusage.add_field("ru_nswap".to_string(), CType::long());
    rusage.add_field("ru_inblock".to_string(), CType::long());
    rusage.add_field("ru_oublock".to_string(), CType::long());
    rusage.add_field("ru_msgsnd".to_string(), CType::long());
    rusage.add_field("ru_msgrcv".to_string(), CType::long());
    rusage.add_field("ru_nsignals".to_string(), CType::long());
    rusage.add_field("ru_nvcsw".to_string(), CType::long());
    rusage.add_field("ru_nivcsw".to_string(), CType::long());
    rusage.finalize();
    db.add_type("struct rusage", CType::Struct(rusage));

    // struct utsname
    let mut utsname = StructType::new(Some("utsname".to_string()));
    utsname.add_field("sysname".to_string(), CType::array(CType::char(), Some(65)));
    utsname.add_field("nodename".to_string(), CType::array(CType::char(), Some(65)));
    utsname.add_field("release".to_string(), CType::array(CType::char(), Some(65)));
    utsname.add_field("version".to_string(), CType::array(CType::char(), Some(65)));
    utsname.add_field("machine".to_string(), CType::array(CType::char(), Some(65)));
    utsname.add_field("domainname".to_string(), CType::array(CType::char(), Some(65)));
    utsname.finalize();
    db.add_type("struct utsname", CType::Struct(utsname));

    // struct sigaction (simplified)
    let mut sigaction = StructType::new(Some("sigaction".to_string()));
    sigaction.add_field("sa_handler".to_string(), CType::ptr(CType::void())); // Actually function pointer
    sigaction.add_field("sa_mask".to_string(), CType::array(CType::ulong(), Some(16))); // sigset_t
    sigaction.add_field("sa_flags".to_string(), CType::int());
    sigaction.add_field("sa_restorer".to_string(), CType::ptr(CType::void()));
    sigaction.finalize();
    db.add_type("struct sigaction", CType::Struct(sigaction));

    // epoll types
    let mut epoll_event = StructType::new(Some("epoll_event".to_string()));
    epoll_event.packed = true; // epoll_event is packed on x86_64
    epoll_event.add_field("events".to_string(), CType::uint());
    epoll_event.add_field("data".to_string(), CType::ulonglong()); // epoll_data_t union
    epoll_event.finalize();
    db.add_type("struct epoll_event", CType::Struct(epoll_event));

    // Linux-specific syscall functions
    db.add_function(
        FunctionPrototype::new("stat", CType::int())
            .param("pathname", CType::ptr(CType::char()))
            .param("statbuf", CType::ptr(CType::Named("struct stat".to_string())))
            .doc("Get file status")
    );

    db.add_function(
        FunctionPrototype::new("fstat", CType::int())
            .param("fd", CType::int())
            .param("statbuf", CType::ptr(CType::Named("struct stat".to_string())))
            .doc("Get file status by fd")
    );

    db.add_function(
        FunctionPrototype::new("lstat", CType::int())
            .param("pathname", CType::ptr(CType::char()))
            .param("statbuf", CType::ptr(CType::Named("struct stat".to_string())))
            .doc("Get file status (don't follow symlinks)")
    );

    db.add_function(
        FunctionPrototype::new("mmap", CType::ptr(CType::void()))
            .param("addr", CType::ptr(CType::void()))
            .param("length", CType::typedef_ref("size_t"))
            .param("prot", CType::int())
            .param("flags", CType::int())
            .param("fd", CType::int())
            .param("offset", CType::typedef_ref("off_t"))
            .doc("Map files or devices into memory")
    );

    db.add_function(
        FunctionPrototype::new("munmap", CType::int())
            .param("addr", CType::ptr(CType::void()))
            .param("length", CType::typedef_ref("size_t"))
            .doc("Unmap files or devices from memory")
    );

    db.add_function(
        FunctionPrototype::new("mprotect", CType::int())
            .param("addr", CType::ptr(CType::void()))
            .param("len", CType::typedef_ref("size_t"))
            .param("prot", CType::int())
            .doc("Set protection on memory region")
    );

    db.add_function(
        FunctionPrototype::new("ioctl", CType::int())
            .param("fd", CType::int())
            .param("request", CType::ulong())
            .variadic()
            .doc("Device control")
    );

    db.add_function(
        FunctionPrototype::new("socket", CType::int())
            .param("domain", CType::int())
            .param("type", CType::int())
            .param("protocol", CType::int())
            .doc("Create an endpoint for communication")
    );

    db.add_function(
        FunctionPrototype::new("bind", CType::int())
            .param("sockfd", CType::int())
            .param("addr", CType::ptr(CType::Named("struct sockaddr".to_string())))
            .param("addrlen", CType::typedef_ref("socklen_t"))
            .doc("Bind a name to a socket")
    );

    db.add_function(
        FunctionPrototype::new("listen", CType::int())
            .param("sockfd", CType::int())
            .param("backlog", CType::int())
            .doc("Listen for connections on a socket")
    );

    db.add_function(
        FunctionPrototype::new("accept", CType::int())
            .param("sockfd", CType::int())
            .param("addr", CType::ptr(CType::Named("struct sockaddr".to_string())))
            .param("addrlen", CType::ptr(CType::typedef_ref("socklen_t")))
            .doc("Accept a connection on a socket")
    );

    db.add_function(
        FunctionPrototype::new("connect", CType::int())
            .param("sockfd", CType::int())
            .param("addr", CType::ptr(CType::Named("struct sockaddr".to_string())))
            .param("addrlen", CType::typedef_ref("socklen_t"))
            .doc("Initiate a connection on a socket")
    );

    db.add_function(
        FunctionPrototype::new("send", CType::typedef_ref("ssize_t"))
            .param("sockfd", CType::int())
            .param("buf", CType::ptr(CType::void()))
            .param("len", CType::typedef_ref("size_t"))
            .param("flags", CType::int())
            .doc("Send a message on a socket")
    );

    db.add_function(
        FunctionPrototype::new("recv", CType::typedef_ref("ssize_t"))
            .param("sockfd", CType::int())
            .param("buf", CType::ptr(CType::void()))
            .param("len", CType::typedef_ref("size_t"))
            .param("flags", CType::int())
            .doc("Receive a message from a socket")
    );

    db.add_function(
        FunctionPrototype::new("epoll_create", CType::int())
            .param("size", CType::int())
            .doc("Create an epoll instance")
    );

    db.add_function(
        FunctionPrototype::new("epoll_ctl", CType::int())
            .param("epfd", CType::int())
            .param("op", CType::int())
            .param("fd", CType::int())
            .param("event", CType::ptr(CType::Named("struct epoll_event".to_string())))
            .doc("Control interface for an epoll file descriptor")
    );

    db.add_function(
        FunctionPrototype::new("epoll_wait", CType::int())
            .param("epfd", CType::int())
            .param("events", CType::ptr(CType::Named("struct epoll_event".to_string())))
            .param("maxevents", CType::int())
            .param("timeout", CType::int())
            .doc("Wait for an I/O event on an epoll file descriptor")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtin::posix::load_posix_types;

    #[test]
    fn test_linux_types() {
        let mut db = TypeDatabase::new();
        load_posix_types(&mut db);
        load_linux_types(&mut db);

        assert!(db.has_type("struct stat"));
        assert!(db.has_type("struct dirent"));
        assert!(db.has_function("mmap"));
        assert!(db.has_function("socket"));
    }

    #[test]
    fn test_struct_stat_fields() {
        let mut db = TypeDatabase::new();
        load_posix_types(&mut db);
        load_linux_types(&mut db);

        let field = db.format_field_access("struct stat", 0);
        assert_eq!(field, Some(".st_dev".to_string()));

        let field = db.format_field_access("struct stat", 48);
        assert_eq!(field, Some(".st_size".to_string()));
    }
}
