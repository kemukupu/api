use std::path::{Path, PathBuf};

use models::ResponseBuilder;
use rocket::fs::NamedFile;

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate diesel;

mod common;
mod error;
mod models;
#[rustfmt::skip]
mod schema;

use diesel::prelude::*;
use lazy_static::lazy_static;
use rocket::http::Status;
use rocket::response::Redirect;
use rocket::serde::json::Json;
use std::env::var;
/// Database connection
#[rocket_sync_db_pools::database("postgres_database")]
struct UsersDbConn(diesel::PgConnection);

// Thinking about endpoints
// GET api/v1/student/{id}, request information about a user, must contain AUTH header with their token.
// POST api/v1/student/login, to request an access (JWT) token, must attach login details in body
// DELETE api/v1/student/{id}, to remove a user
// GET api/v1/highscores, to request a list of all the high scores
// POST /api/va/highscore, to add a new score - must contain information about the user

// TODO General todos
// Move common DB requests (such as looking up a user) into a framework under common.rs to avoid duplicate code.

lazy_static! {
    static ref JWT_SECRET: String = var("JWT_SECRET").unwrap();
    static ref JWT_EXPIRY_TIME_HOURS: usize =
        var("JWT_EXPIRY_TIME_HOURS").unwrap().parse().unwrap();
    static ref BROWSER_BASE_URL: String = var("BROWSER_BASE_URL").unwrap();
}

/// Return information about the student
#[get("/api/v1/student")]
async fn get_student(token: models::Claims, conn: UsersDbConn) -> models::Response {
    //Load the item from the db, if it exists
    use crate::schema::users::dsl::*;
    let r: Option<crate::models::User> = conn
        .run(move |c| {
            let r = users
                .filter(id.eq(token.sub))
                .limit(1)
                .load::<crate::models::User>(c);
            if let Ok(mut v) = r {
                if v.is_empty() {
                    return None;
                }
                return Some(v.remove(0));
            }
            return None;
        })
        .await;

    // Format and return
    if let Some(user) = r {
        return models::ResponseBuilder {
            data: user,
            status: Status::Ok,
        }
        .build();
    }
    models::ResponseBuilder {
        data: "User Not Found",
        status: Status::BadRequest,
    }
    .build()
}

/// Attempt to login as a student
#[post(
    "/api/v1/student/login",
    data = "<login_information>",
    format = "application/json"
)]
async fn login_student(
    conn: UsersDbConn,
    login_information: Json<models::UserCredentials>,
) -> models::Response {
    let login_information = login_information.into_inner();
    //Check if the user exists in the db
    use crate::schema::users::dsl::*;
    let name = login_information.usr.clone();
    let r: Option<crate::models::User> = conn
        .run(move |c| {
            let r = users
                .filter(usr.eq(name))
                .limit(1)
                .load::<crate::models::User>(c);
            if let Ok(mut v) = r {
                if v.is_empty() {
                    return None;
                }
                return Some(v.remove(0));
            }
            return None;
        })
        .await;

    if r.is_none() {
        return models::ResponseBuilder {
            data: "Incorrect Password or Username",
            status: Status::BadRequest,
        }
        .build();
    }
    let r = r.unwrap();
    //Check that their password hash matches
    let hash_valid = match common::compare_hashed_strings(login_information.pwd, r.pwd) {
        Ok(h) => h,
        Err(e) => {
            return models::ResponseBuilder {
                data: format!("Failed to compare hashes {}", e.to_string()),
                status: Status::InternalServerError,
            }
            .build()
        }
    };

    if !hash_valid {
        return models::ResponseBuilder {
            data: "Incorrect Password or Username",
            status: Status::BadRequest,
        }
        .build();
    }

    return models::ResponseBuilder {
        data: models::Claims::new_token(r.id),
        status: Status::Ok,
    }
    .build();
}

/// Create a new student
#[post(
    "/api/v1/student/create",
    data = "<new_user>",
    format = "application/json"
)]
async fn create_student(
    conn: UsersDbConn,
    new_user: Json<models::UserCredentials>,
) -> models::Response {
    //Check their password meets minimum requirements
    let new_user = new_user.into_inner();
    if new_user.pwd.len() < 8 {
        return models::ResponseBuilder {
            data: "Password Too Short",
            status: Status::BadRequest,
        }
        .build();
    }

    //Check that the username isnt't taken
    use crate::schema::users::dsl::*;
    let name = new_user.usr.clone();
    let r: Option<crate::models::User> = conn
        .run(move |c| {
            let r = users
                .filter(usr.eq(name))
                .limit(1)
                .load::<crate::models::User>(c);
            if let Ok(mut v) = r {
                if v.is_empty() {
                    return None;
                }
                return Some(v.remove(0));
            }
            return None;
        })
        .await;

    if r.is_some() {
        return models::ResponseBuilder {
            data: "Username Taken",
            status: Status::BadRequest,
        }
        .build();
    }

    //Hash password
    let hashed_password = match common::hash_string_with_salt(new_user.pwd) {
        Ok(p) => p,
        Err(e) => {
            return models::ResponseBuilder {
                data: format!("Unable to hash password {}", e.to_string()),
                status: Status::InternalServerError,
            }
            .build()
        }
    };

    let new_user = models::UserCredentials {
        usr: new_user.usr,
        pwd: hashed_password,
    };

    //Save account in db
    use schema::users;
    let r: Result<models::User, diesel::result::Error> = conn
        .run(move |c| {
            diesel::insert_into(users::table)
                .values(new_user)
                .get_result(c)
        })
        .await;

    if let Err(e) = r {
        return models::ResponseBuilder {
            data: format!("Failed to insert into server {}", e.to_string()),
            status: Status::InternalServerError,
        }
        .build();
    }

    return models::ResponseBuilder {
        data: models::Claims::new_token(r.unwrap().id),
        status: Status::Created,
    }
    .build();
}

#[delete("/api/v1/student")]
async fn delete_student(token: models::Claims, conn: UsersDbConn) -> models::Response {
    //Check the user exists
    use crate::schema::users::dsl::*;
    let usr_id = token.sub.clone();
    let r: Option<crate::models::User> = conn
        .run(move |c| {
            let r = users
                .filter(id.eq(usr_id))
                .limit(1)
                .load::<crate::models::User>(c);
            if let Ok(mut v) = r {
                if v.is_empty() {
                    return None;
                }
                return Some(v.remove(0));
            }
            return None;
        })
        .await;

    if r.is_none() {
        return models::ResponseBuilder {
            data: "User Not Found",
            status: Status::BadRequest,
        }
        .build();
    }

    //Delete student from db
    let r: Result<crate::models::User, diesel::result::Error> = conn
        .run(move |c| diesel::delete(users.filter(id.eq(token.sub))).get_result(c))
        .await;

    if let Err(e) = r {
        return models::ResponseBuilder {
            data: format!("Unable to delete user due to error {}", e.to_string()),
            status: Status::InternalServerError,
        }
        .build();
    }

    return models::ResponseBuilder {
        data: format!("Account {} deleted", r.unwrap().usr),
        status: Status::Ok,
    }
    .build();
}

#[get("/api/v1/scores?<offset>&<limit>&<usr>&<id>")]
async fn get_scores(
    conn: UsersDbConn,
    offset: Option<i64>,
    limit: Option<i64>,
    usr: Option<String>,
    mut id: Option<i32>,
) -> models::Response {
    //Set the defaults for these values, and ensure non-negative
    let offset: i64 = offset.unwrap_or(0).abs();
    let limit: i64 = limit.unwrap_or(10).abs(); 

    if id.is_none() && usr.is_some() {
        //Load the id of the user suggested
        use crate::schema::users::dsl::{usr as usr_struct, users};
        let r: Option<crate::models::User> = conn
        .run(move |c| {
            let r = users
                .filter(usr_struct.eq(usr.unwrap()))
                .limit(1)
                .load::<crate::models::User>(c);
            if let Ok(mut v) = r {
                if v.is_empty() {
                    return None;
                }
                return Some(v.remove(0));
            }
            return None;
        })
        .await;
        if let Some(found_user) = r {
            id = Some(found_user.id);
        }
    }

    use crate::schema::scores::dsl::{usr_id as struct_id};
    let r: Result<Vec<models::Score>, diesel::result::Error> = conn
        .run(move |c| {
            let mut db_request = crate::schema::scores::table.into_boxed();
            if let Some(usr_id) = id {
                db_request = db_request.filter(struct_id.eq(usr_id));
            }
            db_request
                .limit(limit)
                .offset(offset)
                .load::<crate::models::Score>(c)
        }
    ).await;
    
    if let Err(e) = r {
        return models::ResponseBuilder {
            data: format!("Failed to query the server due to error {}", e.to_string()),
            status: Status::InternalServerError,
        }
        .build();
    }

    let r = r.unwrap();
    if r.is_empty() {
        let data: Vec<()> = vec![];
        return models::ResponseBuilder {
            data,
            status: Status::NoContent,
        }.build()
    }
    models::ResponseBuilder {
        data: r,
        status: Status::Ok,
    }
    .build()
}

#[post("/api/v1/scores", data = "<new_score>", format = "application/json")]
async fn add_score(
    token: models::Claims,
    new_score: Json<models::NewScore>,
    conn: UsersDbConn,
) -> models::Response {
    let new_score = new_score.into_inner();
    //Assign the user id
    let new_score = models::Score {
        id: 0, //doesn't matter, is automatically assigned in the schema
        usr_id: token.sub,
        score: new_score.score,
    };

    use schema::scores;
    let r: Result<_, diesel::result::Error> = conn
        .run(move |c| {
            diesel::insert_into(scores::table)
                .values(new_score)
                .execute(c)
        })
        .await;

    if let Err(e) = r {
        return models::ResponseBuilder {
            data: format!("Failed to insert into server {}", e.to_string()),
            status: Status::InternalServerError,
        }
        .build();
    }

    return models::ResponseBuilder {
        data: "",
        status: Status::Created,
    }
    .build();
}

/// Serve docs about the api
#[get("/api/docs")]
async fn docs() -> NamedFile {
    NamedFile::open(Path::new("static/docs/static.html"))
        .await
        .ok()
        .unwrap()
}

/// Returns the current health status of the database
#[get("/api/health")]
fn health() -> models::Response {
    //TODO
    ResponseBuilder {
        data: "Online",
        status: Status::Ok,
    }
    .build()
}

/// Handle the serving of any static resources for various pages
/// SAFETY: Rocket has a neat implementation preventing a path from getting outside of /static - keeping our host safe.
#[get("/api/static/<file..>")]
async fn website_resource(file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new("static/").join(file)).await.ok()
}

/// Handle any 404's
#[catch(404)]
async fn not_found() -> Redirect {
    Redirect::to("/notfound")
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .register("/", catchers![not_found])
        .mount(
            "/",
            routes![
                docs,
                get_student,
                login_student,
                create_student,
                delete_student,
                get_scores,
                add_score,
                website_resource,
                health,
            ],
        )
        .attach(UsersDbConn::fairing())
}
