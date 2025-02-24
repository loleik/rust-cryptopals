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
                .arg(arg!(<CHALLENGE> "Set number"))
                .arg(arg!(<INPUT> "Input string or file path"))
                .arg_required_else_help(true)
        )
}

fn main() {
    let matches: clap::ArgMatches = cli().get_matches();

    match matches.subcommand() {
        Some(("run", sub_matches)) => {
            let challenge: usize = sub_matches.get_one::<String>("CHALLENGE")
                    .expect("Required")
                    .parse().expect("Invalid set number");
            let input: &String = sub_matches.get_one::<String>("INPUT").expect("Required");

            match challenge {
                1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 => 
                    set1::set_1(&challenge, &input),
                9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 => 
                    set2::set_2(&challenge, &input),
                _ => println!("Invalid challenge number: {}", challenge),
            }
        },
        _ => println!("Invalid subcommand: {}", matches.subcommand().unwrap().0),
    }
}