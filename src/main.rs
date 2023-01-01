use actix_web::{error, get, web, App, HttpResponse, HttpServer, Responder};
use actix_web::middleware::Logger;
use dotenv::dotenv;
use env_logger::Env;

mod database;
mod health;
mod mail;
mod models;
mod routes;
mod schema;
mod utils;

#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    format!("Hello {}!", name)
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let pool = database::get_pool();
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Logger::new("%a - %D ms - %T s %{User-Agent}i"))
            .app_data(web::Data::new(pool.clone()))
            .service(routes::test_database)
            .configure(routes::configure)
            .app_data(web::JsonConfig::default().error_handler(|err, _req| {
                error::InternalError::from_response(
                    "",
                    HttpResponse::BadRequest()
                        .content_type("application/json")
                        .body(format!(r#"{{"error":"{}"}}"#, err)),
                )
                .into()
            }))
            .service(greet)
    })
    .bind(("0.0.0.0", 8088))?
    .workers(2)
    .run()
    .await
}
