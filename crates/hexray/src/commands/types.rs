//! Type library management commands.
//!
//! Commands for managing C type libraries used during decompilation
//! for struct field resolution and function prototypes.

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use hexray_types::TypeDatabase;
use std::fs;
use std::path::PathBuf;

/// Type library management actions.
#[derive(Subcommand)]
pub enum TypesAction {
    /// List builtin type databases
    Builtin,
    /// List types in a type database
    List {
        /// Type category: "posix", "linux", "macos", or "libc"
        category: String,
        /// Show only structs
        #[arg(long)]
        structs: bool,
        /// Show only functions
        #[arg(long)]
        functions: bool,
    },
    /// Show details of a specific type
    Show {
        /// Type name (e.g., "struct stat", "size_t", "printf")
        name: String,
        /// Type category: "posix", "linux", "macos", or "libc"
        #[arg(short, long, default_value = "posix")]
        category: String,
    },
    /// Parse a C header file and show extracted types
    Parse {
        /// Path to C header file
        header: PathBuf,
    },
    /// List all types available for decompilation
    All,
}

/// Handle types management commands.
pub fn handle_types_command(action: TypesAction) -> Result<()> {
    use hexray_types::builtin::{libc, linux, macos, posix};

    match action {
        TypesAction::Builtin => {
            println!("Available builtin type databases:");
            println!("{}", "=".repeat(40));
            println!("  posix  - POSIX types (size_t, pid_t, struct timeval, etc.)");
            println!("  linux  - Linux-specific types (struct stat, mmap, socket, etc.)");
            println!("  macos  - macOS-specific types (mach_port_t, dispatch_*, etc.)");
            println!("  libc   - Standard C library functions (printf, malloc, etc.)");
        }

        TypesAction::List {
            category,
            structs,
            functions,
        } => {
            let mut db = TypeDatabase::new();

            match category.to_lowercase().as_str() {
                "posix" => posix::load_posix_types(&mut db),
                "linux" => {
                    posix::load_posix_types(&mut db);
                    linux::load_linux_types(&mut db);
                }
                "macos" => {
                    posix::load_posix_types(&mut db);
                    macos::load_macos_types(&mut db);
                }
                "libc" => {
                    posix::load_posix_types(&mut db);
                    libc::load_libc_functions(&mut db);
                }
                _ => bail!(
                    "Unknown category '{}'. Use: posix, linux, macos, or libc",
                    category
                ),
            }

            println!("Types in '{}' database:", category);
            println!("{}", "=".repeat(50));

            if !functions {
                println!("\nTypes/Typedefs:");
                for name in db.type_names() {
                    if structs && !name.starts_with("struct ") {
                        continue;
                    }
                    println!("  {}", name);
                }
            }

            if !structs {
                println!("\nFunctions:");
                for name in db.function_names() {
                    println!("  {}()", name);
                }
            }
        }

        TypesAction::Show { name, category } => {
            let mut db = TypeDatabase::new();

            match category.to_lowercase().as_str() {
                "posix" => posix::load_posix_types(&mut db),
                "linux" => {
                    posix::load_posix_types(&mut db);
                    linux::load_linux_types(&mut db);
                }
                "macos" => {
                    posix::load_posix_types(&mut db);
                    macos::load_macos_types(&mut db);
                }
                "libc" => {
                    posix::load_posix_types(&mut db);
                    libc::load_libc_functions(&mut db);
                }
                _ => bail!(
                    "Unknown category '{}'. Use: posix, linux, macos, or libc",
                    category
                ),
            }

            // Try as a type first
            if db.get_type(&name).is_some() {
                println!("Type: {}", name);
                println!("{}", "=".repeat(40));
                println!("{}", db.format_type(&name));
            } else if let Some(func) = db.get_function(&name) {
                println!("Function: {}", name);
                println!("{}", "=".repeat(40));
                println!("{}", func.format());
            } else {
                bail!(
                    "Type or function '{}' not found in '{}' database",
                    name,
                    category
                );
            }
        }

        TypesAction::Parse { header } => {
            let content = fs::read_to_string(&header)
                .with_context(|| format!("Failed to read header: {}", header.display()))?;

            let parser = hexray_types::Parser::new(&content)
                .with_context(|| format!("Failed to parse header: {}", header.display()))?;
            let db = parser
                .parse()
                .with_context(|| format!("Failed to parse header: {}", header.display()))?;

            println!("Parsed types from {}:", header.display());
            println!("{}", "=".repeat(50));

            println!("\nTypes:");
            for name in db.type_names() {
                println!("  {}", name);
            }

            println!("\nFunctions:");
            for name in db.function_names() {
                println!("  {}()", name);
            }
        }

        TypesAction::All => {
            let mut db = TypeDatabase::new();
            posix::load_posix_types(&mut db);
            linux::load_linux_types(&mut db);
            macos::load_macos_types(&mut db);
            libc::load_libc_functions(&mut db);

            println!(
                "All available types ({} types, {} functions):",
                db.type_names().count(),
                db.function_names().count()
            );
            println!("{}", "=".repeat(50));

            println!("\nTypes:");
            for name in db.type_names() {
                println!("  {}", name);
            }

            println!("\nFunctions:");
            for name in db.function_names() {
                println!("  {}()", name);
            }
        }
    }

    Ok(())
}
