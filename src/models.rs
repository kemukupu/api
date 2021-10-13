use crate::schema::*;
use crate::{JWT_EXPIRY_TIME_HOURS, JWT_SECRET};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rocket::http::{ContentType, Status};
use rocket::request::{self, FromRequest, Request};
use rocket::serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

fn wrap(s: String) -> String {
    format!("{{\"data\": {}}}", s)
}

/// A user stored in the database
#[derive(Queryable, Serialize, Clone)]
pub struct User {
    pub id: i32,
    pub usr: String,
    #[serde(skip_serializing)]
    pub pwd: String, //Hashed
}

/// A score uploaded by a user
#[derive(Queryable, Serialize)]
pub struct Score {
    pub id: i32,
    pub usr_id: i32,
    pub score: i32,
}

#[derive(Deserialize)]
pub struct NewScore {
    pub score: i32,
}

#[derive(Insertable)]
#[table_name = "scores"]

pub struct InsertableScore {
    pub score: i32,
    pub usr_id: i32,
}

/// User credentials, to be used when logging in or creating a new account
#[derive(Deserialize, Insertable)]
#[table_name = "users"]
pub struct UserCredentials {
    pub usr: String,
    pub pwd: String,
}

#[derive(Debug)]
pub struct Response {
    body: String,
    status: Status,
}

/// Represents a basic JSON response from the api
pub struct ResponseBuilder<T>
where
    T: Serialize,
{
    pub data: T,
    pub status: Status,
}

impl<T> ResponseBuilder<T>
where
    T: Serialize,
{
    pub fn build(self) -> Response {
        let body = match serde_json::to_string(&self.data) {
            Ok(b) => b,
            Err(e) => {
                return Response {
                    body: wrap(format!(
                        "Failed to serialize obejct to json {}",
                        e.to_string()
                    )),
                    status: Status::InternalServerError,
                }
            }
        };
        Response {
            body: wrap(body),
            status: self.status,
        }
    }
}

impl Default for ResponseBuilder<String> {
    fn default() -> ResponseBuilder<String> {
        ResponseBuilder {
            data: "".into(),
            status: Status::Ok,
        }
    }
}

#[rocket::async_trait]
impl<'r> rocket::response::Responder<'r, 'static> for Response {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        rocket::response::Response::build()
            .header(ContentType::new("application", "json"))
            .status(self.status)
            .sized_body(self.body.len(), Cursor::new(self.body))
            .ok()
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
        let curr_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards!")
            .as_secs() as usize;
        let c: Claims = Claims {
            exp: curr_time + *JWT_EXPIRY_TIME_HOURS * 60 * 60,
            iat: curr_time,
            sub,
        };
        encode(
            &Header::default(),
            &c,
            &EncodingKey::from_secret((*JWT_SECRET).as_ref()),
        )
        .unwrap() // HACK this secret should be loaded in from env
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Claims {
    type Error = Response;
    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Response> {
        //TODO improve the headers here, so we will check for Authorization along with Authorisation.
        //Should help the americanally challenged of us...
        let auth_header = req.headers().get_one("Authorisation");
        if auth_header.is_none() {
            return request::Outcome::Failure((
                Status::Unauthorized,
                ResponseBuilder {
                    data: "Authorisation Header Not Present",
                    status: Status::Unauthorized,
                }
                .build(),
            ));
        }

        match decode::<Claims>(
            &auth_header.unwrap(),
            &DecodingKey::from_secret((*JWT_SECRET).as_ref()),
            &Validation::default(),
        ) {
            Ok(t) => {
                //TODO validate the user hasn't been deleted (check db)
                request::Outcome::Success(t.claims)
            }
            Err(_) => request::Outcome::Failure((
                Status::Unauthorized,
                ResponseBuilder {
                    data: "Invalid Auth Token",
                    status: Status::Unauthorized,
                }
                .build(),
            )),
        }
    }
}
