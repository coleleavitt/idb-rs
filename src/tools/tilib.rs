pub use idb_rs::til::print::{named_decl, symbol_decl, type_decl, udt_layout};
use idb_rs::til::print::{print_til_section, PrintOptions};

use crate::{get_til_section, Args, PrintTilibArgs};

pub fn tilib_print(
    args: &Args,
    tilib_args: &PrintTilibArgs,
) -> anyhow::Result<()> {
    let til = get_til_section(args)?;
    let options = PrintOptions {
        dump_struct_layout: tilib_args.dump_struct_layout,
    };
    print_til_section(std::io::stdout(), &til, &options)?;
    Ok(())
}
