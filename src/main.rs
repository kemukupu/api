use std::collections::HashMap;
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
use toml::value::Table;
/// Database connection
#[rocket_sync_db_pools::database("postgres_database")]
struct UsersDbConn(diesel::PgConnection);

// TODO General todos
// Move common DB requests (such as looking up a user) into a framework under common.rs to avoid duplicate code.
// Modify get requests to support 500 server-failure errors if the db is unable to be accessed, rather than the current option-based solution
// Move token boilerplate into a macro

lazy_static! {
    static ref JWT_SECRET: String = var("JWT_SECRET").expect("Env var JWT_SECRET not set!");
    static ref JWT_EXPIRY_TIME_HOURS: usize =
        var("JWT_EXPIRY_TIME_HOURS").expect("Env var JWT_EXPIRY_TIME_HOURS not set!").parse().unwrap();
    static ref BROWSER_BASE_URL: String = var("BROWSER_BASE_URL").expect("Env var BROWSER_BASE_URL not set!");
    static ref COSTUMES: HashMap<String, models::Costume> = {
        //Load data from file, and parse as toml
        let data = std::fs::read_to_string("./costume.toml").expect("Unable to find `./costume.toml`");
        let f = data.parse::<toml::Value>().expect("Unable to parse `./costume.toml`");

        let costumes: &Table = f.get("costume")
            .expect("Unable to parse `./costume.toml`, no costumes provided!")
            .as_table()
            .expect("costume tag is not a table in `./costume.toml`");

        //Parse each costume into hashmap
        let mut map: HashMap<String, models::Costume> = HashMap::default();
        let keys: Vec<&String> = costumes.keys().into_iter().collect();
        for key in keys {
            let costume = costumes
                .get(key)
                .expect(&format!("Unable to parse costume {} from `./costume.toml`, is it correctly formatted?", key))
                .as_table()
                .expect(&format!("Unable to parse {} as table from `./costume.toml`", key));
            let display_name: String = costume
                .get("name")
                .expect(&format!("Unable to parse name for costume {} from `./costume.toml`", key))
                .as_str()
                .expect(&format!("Unable to parse name for costume {} from `./costume.toml`", key))
                .to_owned();
            let description: String = costume
                .get("description")
                .expect(&format!("Unable to parse description for costume {} from `./costume.toml`", key))
                .as_str()
                .expect(&format!("Unable to parse name for costume {} from `./costume.toml`", key))
                .to_owned();
            let price: usize = costume
                .get("price")
                .expect(&format!("Unable to parse price for costume {} from `./costume.toml`", key))
                .as_integer()
                .expect(&format!("Unable to parse description for costume {} from `./costume.toml`", key)) as usize;
            map.insert(key.clone(), models::Costume {
                name: key.clone(),
                display_name,
                description,
                price,
            });
        }

        return map;
    };
    static ref ACHIEVEMENTS: HashMap<String, models::Achievement> = {
        let data = std::fs::read_to_string("./achievement.toml").expect("Unable to find `./achievement.toml`");
        let f = data.parse::<toml::Value>().expect("Unable to parse `./achievement.toml`");

        let achievements: &Table = f.get("achievement")
            .expect("Unable to parse `./achievement.toml`, no achievements provided!")
            .as_table()
            .expect("achievement tag is not a table in `./achievement.toml`");

        let mut map: HashMap<String, models::Achievement> = HashMap::default();
        let keys: Vec<&String> = achievements.keys().into_iter().collect();
        for key in keys {
            let achievement = achievements
                .get(key)
                .expect(&format!("Unable to parse achievement {} from `./achievement.toml`, is it correctly formatted?", key))
                .as_table()
                .expect(&format!("Unable to parse {} as table from `./achievement.toml`", key));
            let display_name: String = achievement
                .get("name")
                .expect(&format!("Unable to parse name for achievement {} from `./achievement.toml`", key))
                .as_str()
                .expect(&format!("Unable to parse name for achievement {} from `./achievement.toml`", key))
                .to_owned();
            let description: String = achievement
                .get("description")
                .expect(&format!("Unable to parse description for achievement {} from `./achievement.toml`", key))
                .as_str()
                .expect(&format!("Unable to parse name for achievement {} from `./achievement.toml`", key))
                .to_owned();
            map.insert(key.clone(), models::Achievement {
                name: key.clone(),
                display_name,
                description,
            });
        }
        return map;
    };
}

/// Return information about the student
#[get("/api/v1/student")]
async fn get_student(
    token: Result<models::Claims, models::Response>,
    conn: UsersDbConn,
) -> models::Response {
    if let Err(e) = token {
        return e;
    }
    let token = token.unwrap();
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
async fn create_student(conn: UsersDbConn, new_user: Json<models::NewUser>) -> models::Response {
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

    let new_user = models::NewUser {
        usr: new_user.usr,
        pwd: hashed_password,
        nickname: new_user.nickname,
        current_costume: "default".into(),
        costumes: vec!["default".into()],
        achievements: vec![],
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
async fn delete_student(
    token: Result<models::Claims, models::Response>,
    conn: UsersDbConn,
) -> models::Response {
    if let Err(e) = token {
        return e;
    }
    let token = token.unwrap();
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

    //Delete all of this users scores from the db
    {
        use crate::schema::scores::dsl::*;
        let subject = token.sub;
        let r: Result<_, diesel::result::Error> = conn
            .run(move |c| diesel::delete(scores.filter(usr_id.eq(subject))).execute(c))
            .await;
    
        if let Err(e) = r {
            return models::ResponseBuilder {
                data: format!("Unable to delete users scores due to error {}", e.to_string()),
                status: Status::InternalServerError,
            }
            .build();
        }
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
    let limit: i64 = limit.unwrap_or(100).abs();

    if id.is_none() && usr.is_some() {
        //Load the id of the user suggested
        use crate::schema::users::dsl::{users, usr as usr_struct};
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
        } else {
            let data: Vec<()> = vec![];
            return models::ResponseBuilder {
                data,
                status: Status::Ok,
            }
            .build();
        }
    }

    use crate::schema::scores::dsl::usr_id as struct_id;
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
        })
        .await;

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
            status: Status::Ok,
        }
        .build();
    }
    models::ResponseBuilder {
        data: r,
        status: Status::Ok,
    }
    .build()
}

#[post("/api/v1/scores", data = "<new_score>", format = "application/json")]
async fn add_score(
    token: Result<models::Claims, models::Response>,
    new_score: Json<models::NewScore>,
    conn: UsersDbConn,
) -> models::Response {
    if let Err(e) = token {
        return e;
    }
    let token = token.unwrap();
    let new_score = new_score.into_inner();
    //Assign the user id
    let new_score = models::InsertableScore {
        usr_id: token.sub,
        num_stars: new_score.num_stars,
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

#[get("/api/v1/student/costumes")]
async fn get_costumes(
    token: Result<models::Claims, models::Response>,
    conn: UsersDbConn,
) -> models::Response {
    if let Err(e) = token {
        return e;
    }
    let token = token.unwrap();
    //Load the user requested
    let search_id = token.sub;
    use crate::schema::users::dsl::*;
    let r: Result<Option<crate::models::User>, diesel::result::Error> = conn
        .run(move |c| {
            let r = users
                .filter(id.eq(search_id))
                .limit(1)
                .load::<crate::models::User>(c);
            return match r {
                Ok(mut v) => {
                    if v.is_empty() {
                        return Ok(None);
                    }
                    Ok(Some(v.remove(0)))
                }
                Err(e) => Err(e),
            };
        })
        .await;

    //Check request is ok
    if let Err(e) = r {
        return models::ResponseBuilder {
            data: format!("Failed to query the server due to error {}", e.to_string()),
            status: Status::InternalServerError,
        }
        .build();
    }
    let r = r.unwrap();

    //Check user exists
    if r.is_none() {
        return models::ResponseBuilder {
            data: "User not found in database!",
            status: Status::NotFound,
        }
        .build();
    }

    //Return value
    return models::ResponseBuilder {
        data: r.unwrap().costumes,
        status: Status::Ok,
    }
    .build();
}

#[post("/api/v1/student/<costume>")]
async fn set_user_costume(
    token: Result<models::Claims, models::Response>,
    conn: UsersDbConn,
    costume: String,
) -> models::Response {
    if let Err(e) = token {
        return e;
    }
    let token = token.unwrap();
    if !COSTUMES.contains_key(&costume) {
        return models::ResponseBuilder {
            data: "Costume does not exist",
            status: Status::BadRequest,
        }
        .build();
    }

    //Load costume
    let costume = COSTUMES.get(&costume).unwrap();

    //Load the user requested
    let search_id = token.sub;
    use crate::schema::users::dsl::*;
    let r: Result<crate::models::User, diesel::result::Error> = conn
        .run(move |c| {
            let r: Result<crate::models::User, diesel::result::Error> =
                diesel::update(users.filter(id.eq(search_id)))
                    .set(current_costume.eq(&costume.name))
                    .get_result(c);
            return r;
        })
        .await;

    //Check request is ok
    if let Err(e) = r {
        return models::ResponseBuilder {
            data: format!("Failed to query the server due to error {}", e.to_string()),
            status: Status::InternalServerError,
        }
        .build();
    }
    let r = r.unwrap();

    //Return value
    return models::ResponseBuilder {
        data: r,
        status: Status::Ok,
    }
    .build();
}

#[post(
    "/api/v1/student/costumes",
    data = "<costume>",
    format = "application/json"
)]
async fn unlock_costume(
    token: Result<models::Claims, models::Response>,
    conn: UsersDbConn,
    costume: Json<models::UnlockCostume>,
) -> models::Response {
    if let Err(e) = token {
        return e;
    }
    let token = token.unwrap();
    let costume = costume.into_inner();
    //Check requested costume exists
    if !COSTUMES.contains_key(&costume.name) {
        return models::ResponseBuilder {
            data: "Costume does not exist",
            status: Status::BadRequest,
        }
        .build();
    }

    //Load costume
    let costume = COSTUMES.get(&costume.name).unwrap();

    //Load all scores from this user, and tally them to get their total score
    let search_id = token.sub;
    use crate::schema::scores::dsl::{scores, usr_id};
    let r: Result<Vec<crate::models::Score>, diesel::result::Error> = conn
        .run(move |c| {
            scores
                .filter(usr_id.eq(search_id))
                .load::<crate::models::Score>(c)
        })
        .await;

    //Check request is ok
    if let Err(e) = r {
        return models::ResponseBuilder {
            data: format!("Failed to query the server due to error {}", e.to_string()),
            status: Status::InternalServerError,
        }
        .build();
    }

    //Tally their score
    let mut score = 0;
    for s in r.unwrap() {
        score += s.num_stars;
    }

    //Validate that they have enough stars
    if score < costume.price as i32 {
        return models::ResponseBuilder {
            data: "Costume is too expensive",
            status: Status::BadRequest,
        }
        .build();
    }

    //Modify that user with their new costume!
    let r = conn
        .run(move |c| {
            //HACK currently diesel does not support this sort of array manipulation, but it will come eventually!
            let cmd = format!("UPDATE users SET costumes = (select array_agg(distinct e) from unnest(costumes || '{{{}}}') e) WHERE id={} RETURNING *;", &costume.name, &token.sub);
            diesel::sql_query(&cmd).load::<crate::models::User>(c)
        })
        .await;

    if let Err(e) = r {
        return models::ResponseBuilder {
            data: format!("Failed to query the server due to error {}", e.to_string()),
            status: Status::InternalServerError,
        }
        .build();
    }

    let r = r.unwrap();
    if r.is_empty() {
        return models::ResponseBuilder {
            data: format!("Failed to query the server due to being unable to find user! Was it deleted while this query was running?"),
            status: Status::InternalServerError,
        }
        .build();
    }

    return models::ResponseBuilder {
        data: r.get(0),
        status: Status::Ok,
    }
    .build();
}

#[post(
    "/api/v1/student/achievement",
    data = "<achievement>",
    format = "application/json"
)]
async fn unlock_achievement(
    token: Result<models::Claims, models::Response>,
    conn: UsersDbConn,
    achievement: Json<models::UnlockAchievement>,
) -> models::Response {
    if let Err(e) = token {
        return e;
    }
    let token = token.unwrap();
    //Check relevant achievement exists
    let achievement = achievement.into_inner();
    if !ACHIEVEMENTS.contains_key(&achievement.name) {
        return models::ResponseBuilder {
            data: "Achievement does not exist",
            status: Status::BadRequest,
        }
        .build();
    }

    //Modify that user with new achievement!
    let r = conn
        .run(move |c| {
            //HACK currently diesel does not support this sort of array manipulation, but it will come eventually!
            let cmd = format!("UPDATE users SET achievements = (select array_agg(distinct e) from unnest(achievements || '{{{}}}') e) WHERE id={} RETURNING *;", &achievement.name, &token.sub);
            diesel::sql_query(&cmd).load::<crate::models::User>(c)
        })
        .await;

    if let Err(e) = r {
        return models::ResponseBuilder {
            data: format!("Failed to query the server due to error {}", e.to_string()),
            status: Status::InternalServerError,
        }
        .build();
    }

    let r = r.unwrap();
    if r.is_empty() {
        return models::ResponseBuilder {
            data: format!("Failed to query the server due to being unable to find user! Was it deleted while this query was running?"),
            status: Status::InternalServerError,
        }
        .build();
    }

    return models::ResponseBuilder {
        data: r.get(0),
        status: Status::Ok,
    }
    .build();
}

#[get("/api/v1/costume")]
fn get_costume_information() -> models::Response {
    let data: Vec<models::Costume> = COSTUMES.values().cloned().collect();
    return models::ResponseBuilder {
        data: data,
        status: Status::Ok,
    }
    .build();
}

#[get("/api/v1/costume/image/<costume_id>")]
async fn get_costume_image(costume_id: String) -> Option<NamedFile> {
    NamedFile::open(Path::new(&format!("static/costume/{}", costume_id)))
        .await
        .ok()
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

/// Endpoint mostly used during development, is a final catch-all to prevent infinite loops.
#[get("/notfound")]
fn not_found_stop_point() -> &'static str {
    "Route Not Found"
}

/// Handle any 404's
#[catch(404)]
async fn not_found() -> Redirect {
    Redirect::to("/notfound")
}

#[launch]
fn rocket() -> _ {
    //Initalize all globals
    lazy_static::initialize(&JWT_SECRET);
    lazy_static::initialize(&JWT_EXPIRY_TIME_HOURS);
    lazy_static::initialize(&BROWSER_BASE_URL);
    lazy_static::initialize(&COSTUMES);
    lazy_static::initialize(&ACHIEVEMENTS);
    //Launch rocket
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
                set_user_costume,
                get_scores,
                add_score,
                unlock_costume,
                get_costumes,
                get_costume_information,
                get_costume_image,
                unlock_achievement,
                website_resource,
                health,
                not_found_stop_point,
            ],
        )
        .attach(UsersDbConn::fairing())
}
