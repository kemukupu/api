use crate::schema::*;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};
use rocket::serde::{Deserialize, Serialize};
use crate::{JWT_SECRET, JWT_EXPIRY_TIME_HOURS};
use std::time::{SystemTime, UNIX_EPOCH};
/// A user stored in the database
#[derive(Queryable, Serialize, Clone)]
pub struct User {
    pub id: i32,
    pub usr: String,
    #[serde(skip_serializing)]
    pub pwd: String, //Hashed
}

/// A score uploaded by a user
#[derive(Queryable, Insertable, Serialize)]
#[table_name = "scores"]
pub struct Score {
    pub id: i32,
    pub usr_id: i32,
    pub score: i32,
}

#[derive(Deserialize)]
pub struct NewScore {
    pub score: i32,
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

/// The claims held by the JWT used for authentication
#[derive(Serialize, Deserialize)]
pub struct Claims {
    /// Expiry
    pub exp: usize,
    /// Issued at
    pub iat: usize,
    /// The id of the user who this is for
    pub sub: i32,
}

impl Claims {
    /// Create a new JWT, when provided with the id of the user.
    pub fn new_token(sub: i32) -> String {

        let curr_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards!").as_secs() as usize;    
        let c: Claims = Claims {
            exp: curr_time + JWT_EXPIRY_TIME_HOURS * 60 * 60,
            iat: curr_time,
            sub,
        };
        encode(
            &Header::default(),
            &c,
            &EncodingKey::from_secret(JWT_SECRET.as_ref()),
        )
        .unwrap() // HACK this secret should be loaded in from env
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Claims {
    type Error = String;
    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, String> {
        //TODO improve the headers here, so we will check for Authorization along with Authorisation.
        //Should help the americanally challenged of us...
        let auth_header = req.headers().get_one("Authorisation");
        if auth_header.is_none() {
            return request::Outcome::Failure((
                Status::Unauthorized,
                Response {
                    data: "Authorisation Header Not Present",
                }
                .to_json()
                .unwrap(),
            ));
        }
        match decode::<Claims>(
            &auth_header.unwrap(),
            &DecodingKey::from_secret(JWT_SECRET.as_ref()), //HACK this secret should be loaded in from env
            &Validation::default(),
        ) {
            Ok(t) => request::Outcome::Success(t.claims),
            Err(_) => request::Outcome::Failure((
                Status::Unauthorized,
                Response {
                    data: "Invalid Auth Token",
                }
                .to_json()
                .unwrap(),
            )),
        }
    }
}
