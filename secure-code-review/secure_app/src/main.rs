use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::json;
use std::env;
use std::net::IpAddr;
use std::process::Command;

const DB_NAME: &str = "secure_users.db";

fn init_database() {
    let conn = Connection::open(DB_NAME).expect("Database connection failed");

    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )",
        [],
    )
    .expect("Unable to create users table");
}

#[derive(Deserialize)]
struct LoginQuery {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct UserQuery {
    id: i32,
}

#[derive(Deserialize)]
struct PingQuery {
    host: String,
}

#[get("/")]
async fn home() -> impl Responder {
    HttpResponse::Ok().body(
        r#"
        <h1>CodeAlpha Secure Rust Application</h1>

        <p>
        This version demonstrates remediation of the vulnerabilities
        identified during the secure coding review.
        </p>
        "#,
    )
}

#[get("/login")]
async fn login(query: web::Query<LoginQuery>) -> impl Responder {
    if query.username.len() > 64 || query.password.len() > 128 {
        return HttpResponse::BadRequest().json(json!({
            "error": "Invalid input"
        }));
    }

    let conn = match Connection::open(DB_NAME) {
        Ok(conn) => conn,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Internal server error"
            }))
        }
    };

    // Secure:
    // Parameterized query prevents SQL injection.
    let result = conn.query_row(
        "SELECT username, password_hash
         FROM users
         WHERE username = ?1",
        params![query.username],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
            ))
        },
    );

    let (username, stored_hash) = match result {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::Unauthorized().json(json!({
                "status": "failed"
            }))
        }
    };

    let parsed_hash = match PasswordHash::new(&stored_hash) {
        Ok(hash) => hash,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Invalid stored credential"
            }))
        }
    };

    if Argon2::default()
        .verify_password(query.password.as_bytes(), &parsed_hash)
        .is_ok()
    {
        HttpResponse::Ok().json(json!({
            "status": "success",
            "username": username
        }))
    } else {
        HttpResponse::Unauthorized().json(json!({
            "status": "failed"
        }))
    }
}

#[get("/user")]
async fn get_user(query: web::Query<UserQuery>) -> impl Responder {
    if query.id <= 0 {
        return HttpResponse::BadRequest().json(json!({
            "error": "Invalid user ID"
        }));
    }

    let conn = match Connection::open(DB_NAME) {
        Ok(conn) => conn,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Internal server error"
            }))
        }
    };

    // Secure:
    // Parameterized query.
    let result = conn.query_row(
        "SELECT id, username FROM users WHERE id = ?1",
        params![query.id],
        |row| {
            Ok((
                row.get::<_, i32>(0)?,
                row.get::<_, String>(1)?,
            ))
        },
    );

    match result {
        Ok((id, username)) => HttpResponse::Ok().json(json!({
            "id": id,
            "username": username
        })),

        Err(_) => HttpResponse::NotFound().json(json!({
            "error": "User not found"
        })),
    }
}

#[get("/ping")]
async fn ping_host(query: web::Query<PingQuery>) -> impl Responder {
    // Secure:
    // Only valid IP addresses are accepted.
    let ip: IpAddr = match query.host.parse() {
        Ok(ip) => ip,

        Err(_) => {
            return HttpResponse::BadRequest().json(json!({
                "error": "A valid IP address is required"
            }))
        }
    };

    // Secure:
    // No shell is used.
    // The validated IP is passed as a direct argument.
    let output = match Command::new("ping")
        .args(["-c", "1", &ip.to_string()])
        .output()
    {
        Ok(output) => output,

        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "error": "Ping execution failed"
            }))
        }
    };

    HttpResponse::Ok().json(json!({
        "host": ip.to_string(),
        "output": String::from_utf8_lossy(&output.stdout)
    }))
}

#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "healthy"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    init_database();

    // Secure:
    // Secret is loaded from the environment rather than hardcoded.
    let _secret_key = env::var("APP_SECRET")
        .unwrap_or_else(|_| "development-only-placeholder".to_string());

    println!("Secure demo running on http://127.0.0.1:8081");

    HttpServer::new(|| {
        App::new()
            .service(home)
            .service(login)
            .service(get_user)
            .service(ping_host)
            .service(health)
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}
