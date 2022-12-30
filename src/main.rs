use actix_web::{get, web, App, HttpServer, Responder, error, HttpResponse};
use dotenv::dotenv;

mod database;
mod health;
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

    let pool = database::get_pool();
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(routes::test_database)
            .app_data(web::JsonConfig::default().error_handler(|err, _req| {
                error::InternalError::from_response(
                    "",
                    HttpResponse::BadRequest()
                        .content_type("application/json")
                        .body(format!(r#"{{"error":"{}"}}"#, err)),
                )
                .into()
            }))
            .configure(routes::configure)
            .service(greet)
    })
    .bind(("0.0.0.0", 8088))?
    .workers(2)
    .run()
    .await
}
