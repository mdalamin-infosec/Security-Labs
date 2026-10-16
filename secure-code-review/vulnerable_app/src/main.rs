use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;
use std::process::Command;

// Intentionally hardcoded secret for secure-code-review training.
const SECRET_KEY: &str = "CodeAlpha-Demo-Secret-12345";

const DB_NAME: &str = "demo_users.db";

fn init_database() {
    let conn = Connection::open(DB_NAME).unwrap();

    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )",
        [],
    )
    .unwrap();

    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password)
         VALUES (1, 'admin', 'admin123')",
        [],
    )
    .unwrap();

    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password)
         VALUES (2, 'student', 'password123')",
        [],
    )
    .unwrap();
}

#[derive(Deserialize)]
struct LoginQuery {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct UserQuery {
    id: String,
}

#[derive(Deserialize)]
struct PingQuery {
    host: String,
}

#[get("/")]
async fn home() -> impl Responder {
    HttpResponse::Ok().body(
        r#"
        <h1>CodeAlpha Secure Coding Review</h1>
        <p>Intentionally vulnerable Rust demo application.</p>

        <ul>
            <li>/login?username=admin&password=admin123</li>
            <li>/user?id=1</li>
            <li>/ping?host=127.0.0.1</li>
            <li>/debug-info</li>
        </ul>
        "#,
    )
}

#[get("/login")]
async fn login(query: web::Query<LoginQuery>) -> impl Responder {
    let conn = Connection::open(DB_NAME).unwrap();

    // SECURITY ISSUE:
    // User input is concatenated directly into SQL.
    let sql = format!(
        "SELECT id, username, password FROM users
         WHERE username = '{}' AND password = '{}'",
        query.username, query.password
    );

    let mut statement = conn.prepare(&sql).unwrap();

    let user = statement
        .query_row([], |row| {
            Ok((
                row.get::<_, i32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .ok();

    match user {
        Some((_id, username, _password)) => HttpResponse::Ok().json(json!({
            "status": "success",
            "username": username
        })),

        None => HttpResponse::Unauthorized().json(json!({
            "status": "failed"
        })),
    }
}

#[get("/user")]
async fn get_user(query: web::Query<UserQuery>) -> impl Responder {
    let conn = Connection::open(DB_NAME).unwrap();

    // SECURITY ISSUE:
    // ID is concatenated directly into SQL.
    let sql = format!(
        "SELECT id, username, password FROM users WHERE id = {}",
        query.id
    );

    let mut statement = conn.prepare(&sql).unwrap();

    let user = statement
        .query_row([], |row| {
            Ok((
                row.get::<_, i32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .ok();

    match user {
        Some((id, username, password)) => {
            // SECURITY ISSUE:
            // Sensitive password data is returned to the client.
            HttpResponse::Ok().json(json!({
                "id": id,
                "username": username,
                "password": password
            }))
        }

        None => HttpResponse::NotFound().json(json!({
            "error": "User not found"
        })),
    }
}

#[get("/ping")]
async fn ping_host(query: web::Query<PingQuery>) -> impl Responder {
    // SECURITY ISSUE:
    // Untrusted input is passed to a shell.
    let command = format!("ping -c 1 {}", query.host);

    let output = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
        .unwrap();

    HttpResponse::Ok().json(json!({
        "command": command,
        "stdout": String::from_utf8_lossy(&output.stdout),
        "stderr": String::from_utf8_lossy(&output.stderr)
    }))
}

#[get("/debug-info")]
async fn debug_info() -> impl Responder {
    // SECURITY ISSUE:
    // Sensitive configuration is exposed.
    HttpResponse::Ok().json(json!({
        "secret_key": SECRET_KEY,
        "database": DB_NAME,
        "debug": true
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    init_database();

    println!("Vulnerable demo running on http://127.0.0.1:8080");

    HttpServer::new(|| {
        App::new()
            .service(home)
            .service(login)
            .service(get_user)
            .service(ping_host)
            .service(debug_info)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
