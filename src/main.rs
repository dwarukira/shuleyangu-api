use actix_web::{get, web, App, HttpServer, Responder};

mod database;
mod health;
mod routes;


#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    format!("Hello {}!", name)
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    let pool = database::get_pool();
    HttpServer::new(move || App::new()
    .app_data(web::Data::new(pool.clone()))
    .service(routes::test_database)
    .service(greet))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
