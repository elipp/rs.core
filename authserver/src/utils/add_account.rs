use authserver::Account;
use clap::Parser;
use client::{
    generate_random_bytes, sha1_hash, sha1_hash_iter, to_zero_padded_array, Salt, Verifier,
};
use num_bigint::BigUint;
use tokio_postgres::NoTls;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    username: String,

    #[arg(short, long)]
    password: String,

    #[arg(short, long, default_value_t = 0)]
    gmlevel: u32,
    // #[arg(short, long)]
    // expansion: u32,
}

pub struct Srp6 {
    login: String,
    salt: Salt,
    verifier: Verifier,
}

pub fn calculate_verifier(username_upper: &str, password: &str, salt: &Salt) -> Verifier {
    use client::srp6::{g, N};
    let creds = format!("{}:{}", username_upper, password.to_ascii_uppercase());

    let xb = BigUint::from_bytes_be(&sha1_hash_iter(
        salt.iter().copied().chain(sha1_hash(creds)),
    ));
    let v = g.modpow(&xb, &N);
    to_zero_padded_array(&v.to_bytes_le())
}

#[derive(Debug)]
enum Error {
    AccountAlreadyExists(i32),
    PgError(tokio_postgres::Error),
}

impl From<tokio_postgres::Error> for Error {
    fn from(e: tokio_postgres::Error) -> Self {
        Self::PgError(e)
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();

    assert!(args.username.is_ascii());
    assert!(args.password.is_ascii());

    // PostgreSQL connection string
    let (client, connection) =
        tokio_postgres::connect("host=127.0.0.1 user=auth password=asd dbname=auth", NoTls).await?;

    // Spawn the connection task to manage the connection in the background
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {}", e);
        }
    });

    let username_upper = args.username.to_ascii_uppercase();
    if let Some(account) = client
        .query_opt(
            "SELECT id FROM account WHERE username = $1 LIMIT 1",
            &[&username_upper],
        )
        .await?
    {
        let id: i32 = account.get(0);
        return Err(Error::AccountAlreadyExists(id));
    } else {
        let salt: Salt = generate_random_bytes();
        let verifier = calculate_verifier(&username_upper, &args.password, &salt);
        let new_row = client
            .query_one(
                "INSERT INTO account (username, salt, verifier) VALUES ($1, $2, $3) RETURNING id",
                &[&username_upper, &Vec::from(salt), &Vec::from(verifier)],
            )
            .await?;
        let new_id: i32 = new_row.get(0);
        println!(
            "Inserted new account {} with id {:?}!",
            args.username, new_id
        );
        Ok(())
    }
}