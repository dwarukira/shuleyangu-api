use actix_web::{get, web, App, HttpServer, Responder};
use dotenv::dotenv;


mod database;
mod health;
mod routes;


#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    format!("Hello {}!", name)
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    

    let pool = database::get_pool();
    HttpServer::new(move || App::new()
    .app_data(web::Data::new(pool.clone()))
    .service(routes::test_database)
    .service(greet))
        .bind(("0.0.0.0", 8088))?
        .workers(2)
        .run()
        .await
}
