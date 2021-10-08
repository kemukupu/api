use crate::schema::*;
use rocket::serde::{Deserialize, Serialize};

/// A user stored in the database
#[derive(Queryable, Serialize)]
pub struct User {
    pub id: i32,
    pub usr: String,
    pub pwd: String, //Hashed
}

/// A score uploaded by a user
#[derive(Queryable, Serialize)]
pub struct Score {
    pub id: i32,
    pub usr_id: i32,
    pub score: i32,
}

#[derive(Insertable, Deserialize)]
#[table_name = "scores"]
pub struct NewScore {
    score: i32,
}

/// User credentials, to be used when logging in or creating a new account
#[derive(Deserialize, Insertable)]
#[table_name = "users"]
pub struct UserCredentials {
    pub usr: String,
    pub pwd: String,
}

/// Represents a basic JSON response from the api
#[derive(Serialize)]
pub struct Response<T>
where
    T: Serialize,
{
    pub data: T,
}

impl<T> Response<T>
where
    T: Serialize,
{
    pub fn to_json(self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }
}

impl Default for Response<String> {
    fn default() -> Response<String> {
        Response { data: "".into() }
    }
}
