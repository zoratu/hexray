//! macOS-specific type definitions.
//!
//! This module provides macOS-specific types.

use crate::database::TypeDatabase;
use crate::types::*;

/// Load macOS-specific types into the database.
pub fn load_macos_types(db: &mut TypeDatabase) {
    // macOS uses different struct stat layout
    let mut stat = StructType::new(Some("stat".to_string()));
    stat.add_field("st_dev".to_string(), CType::int());                       // 0
    stat.add_field("st_mode".to_string(), CType::typedef_ref("mode_t"));      // 4
    stat.add_field("st_nlink".to_string(), CType::ushort());                  // 6
    stat.add_field("st_ino".to_string(), CType::typedef_ref("ino_t"));        // 8
    stat.add_field("st_uid".to_string(), CType::typedef_ref("uid_t"));        // 16
    stat.add_field("st_gid".to_string(), CType::typedef_ref("gid_t"));        // 20
    stat.add_field("st_rdev".to_string(), CType::int());                      // 24
    stat.add_field("st_atimespec".to_string(), CType::Named("struct timespec".to_string())); // 32
    stat.add_field("st_mtimespec".to_string(), CType::Named("struct timespec".to_string())); // 48
    stat.add_field("st_ctimespec".to_string(), CType::Named("struct timespec".to_string())); // 64
    stat.add_field("st_birthtimespec".to_string(), CType::Named("struct timespec".to_string())); // 80
    stat.add_field("st_size".to_string(), CType::typedef_ref("off_t"));       // 96
    stat.add_field("st_blocks".to_string(), CType::longlong());               // 104
    stat.add_field("st_blksize".to_string(), CType::int());                   // 112
    stat.add_field("st_flags".to_string(), CType::uint());                    // 116
    stat.add_field("st_gen".to_string(), CType::uint());                      // 120
    stat.add_field("st_lspare".to_string(), CType::int());                    // 124
    stat.add_field("st_qspare".to_string(), CType::array(CType::longlong(), Some(2))); // 128
    stat.finalize();
    db.add_type("struct stat", CType::Struct(stat));

    // Mach types
    db.add_typedef("mach_port_t", CType::uint());
    db.add_typedef("task_t", CType::typedef_ref("mach_port_t"));
    db.add_typedef("thread_t", CType::typedef_ref("mach_port_t"));
    db.add_typedef("vm_address_t", CType::ulong());
    db.add_typedef("vm_size_t", CType::ulong());
    db.add_typedef("kern_return_t", CType::int());

    // struct dirent (macOS)
    let mut dirent = StructType::new(Some("dirent".to_string()));
    dirent.add_field("d_ino".to_string(), CType::typedef_ref("ino_t"));
    dirent.add_field("d_seekoff".to_string(), CType::ulonglong());
    dirent.add_field("d_reclen".to_string(), CType::ushort());
    dirent.add_field("d_namlen".to_string(), CType::ushort());
    dirent.add_field("d_type".to_string(), CType::uchar());
    dirent.add_field("d_name".to_string(), CType::array(CType::char(), Some(1024)));
    dirent.finalize();
    db.add_type("struct dirent", CType::Struct(dirent));

    // kevent structure (kqueue)
    let mut kevent = StructType::new(Some("kevent".to_string()));
    kevent.add_field("ident".to_string(), CType::ulong());
    kevent.add_field("filter".to_string(), CType::short());
    kevent.add_field("flags".to_string(), CType::ushort());
    kevent.add_field("fflags".to_string(), CType::uint());
    kevent.add_field("data".to_string(), CType::long());
    kevent.add_field("udata".to_string(), CType::ptr(CType::void()));
    kevent.finalize();
    db.add_type("struct kevent", CType::Struct(kevent));

    // dispatch types (libdispatch/GCD)
    db.add_typedef("dispatch_queue_t", CType::ptr(CType::Named("dispatch_queue_s".to_string())));
    db.add_typedef("dispatch_block_t", CType::ptr(CType::void()));

    // macOS-specific functions
    db.add_function(
        FunctionPrototype::new("kqueue", CType::int())
            .doc("Create a new kernel event queue")
    );

    db.add_function(
        FunctionPrototype::new("kevent", CType::int())
            .param("kq", CType::int())
            .param("changelist", CType::ptr(CType::Named("struct kevent".to_string())))
            .param("nchanges", CType::int())
            .param("eventlist", CType::ptr(CType::Named("struct kevent".to_string())))
            .param("nevents", CType::int())
            .param("timeout", CType::ptr(CType::Named("struct timespec".to_string())))
            .doc("Kernel event notification mechanism")
    );

    db.add_function(
        FunctionPrototype::new("mach_task_self", CType::typedef_ref("mach_port_t"))
            .doc("Return task port for current task")
    );

    db.add_function(
        FunctionPrototype::new("dispatch_async", CType::void())
            .param("queue", CType::typedef_ref("dispatch_queue_t"))
            .param("block", CType::typedef_ref("dispatch_block_t"))
            .doc("Submit a block for asynchronous execution")
    );

    db.add_function(
        FunctionPrototype::new("dispatch_sync", CType::void())
            .param("queue", CType::typedef_ref("dispatch_queue_t"))
            .param("block", CType::typedef_ref("dispatch_block_t"))
            .doc("Submit a block for synchronous execution")
    );

    db.add_function(
        FunctionPrototype::new("dispatch_get_main_queue", CType::typedef_ref("dispatch_queue_t"))
            .doc("Return the main queue")
    );

    db.add_function(
        FunctionPrototype::new("dispatch_get_global_queue", CType::typedef_ref("dispatch_queue_t"))
            .param("identifier", CType::long())
            .param("flags", CType::ulong())
            .doc("Return a global concurrent queue")
    );

    // Objective-C runtime types
    db.add_typedef("id", CType::ptr(CType::Named("objc_object".to_string())));
    db.add_typedef("Class", CType::ptr(CType::Named("objc_class".to_string())));
    db.add_typedef("SEL", CType::ptr(CType::Named("objc_selector".to_string())));
    db.add_typedef("IMP", CType::ptr(CType::void()));  // Function pointer

    db.add_function(
        FunctionPrototype::new("objc_msgSend", CType::typedef_ref("id"))
            .param("self", CType::typedef_ref("id"))
            .param("op", CType::typedef_ref("SEL"))
            .variadic()
            .doc("Send a message to an object")
    );

    db.add_function(
        FunctionPrototype::new("objc_getClass", CType::typedef_ref("Class"))
            .param("name", CType::ptr(CType::char()))
            .doc("Get a class by name")
    );

    db.add_function(
        FunctionPrototype::new("sel_registerName", CType::typedef_ref("SEL"))
            .param("str", CType::ptr(CType::char()))
            .doc("Register a selector name")
    );

    db.add_function(
        FunctionPrototype::new("class_getName", CType::ptr(CType::char()))
            .param("cls", CType::typedef_ref("Class"))
            .doc("Get the name of a class")
    );

    db.add_function(
        FunctionPrototype::new("object_getClass", CType::typedef_ref("Class"))
            .param("obj", CType::typedef_ref("id"))
            .doc("Get the class of an object")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtin::posix::load_posix_types;

    #[test]
    fn test_macos_types() {
        let mut db = TypeDatabase::new();
        load_posix_types(&mut db);
        load_macos_types(&mut db);

        assert!(db.has_type("struct stat"));
        assert!(db.has_type("struct kevent"));
        assert!(db.has_type("mach_port_t"));
        assert!(db.has_function("kqueue"));
        assert!(db.has_function("dispatch_async"));
    }
}
