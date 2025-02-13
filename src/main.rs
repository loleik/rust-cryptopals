use clap::{arg, Command};

mod set1;
mod set2;
mod utils;

/*
    This is pretty much the git example found here:
    https://github.com/clap-rs/clap/tree/master/examples
*/

fn cli() -> Command {
    Command::new("crypt")
        .about("My implementations of cryptopals challenges")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("run")
                .about("Run a specific part of a set with a specified input")
                .arg(arg!(<SET> "Set number"))
                .arg(arg!(<PART> "Part number"))
                .arg(arg!(<INPUT> "Input string or file path"))
                .arg_required_else_help(true)
        )
}

fn main() {
    let matches: clap::ArgMatches = cli().get_matches();

    match matches.subcommand() {
        Some(("run", sub_matches)) => {
            let set_num: &String = sub_matches.get_one::<String>("SET").expect("Required");
            let part_num: &String = sub_matches.get_one::<String>("PART").expect("Required");
            let input: &String = sub_matches.get_one::<String>("INPUT").expect("Required");

            match set_num.as_str() {
                "1" => set1::set_1(&part_num, &input),
                "2" => set2::set_2(&part_num, &input),
                _ => println!("Invalid set number: {}", set_num),
            }
        },
        _ => println!("Invalid subcommand: {}", matches.subcommand().unwrap().0),
    }
}