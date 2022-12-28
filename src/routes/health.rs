
use actix_web::{
    get,
    HttpResponse,
    web,
};
use serde_json::json;
use crate::database::PostgresPool;
use diesel::RunQueryDsl;

#[get("/health")]
pub async fn test_database(pool: web::Data<PostgresPool>) -> HttpResponse {
    let mut conn = pool.get().unwrap();
    let result = diesel::sql_query("SELECT 1")
        .execute(&mut conn)
        .unwrap();
    HttpResponse::Ok().json({
        json!({
            "status": "ok",
            "result": result
        })
    })
}