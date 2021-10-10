table! {
    scores (id) {
        id -> Int4,
        usr_id -> Int4,
        score -> Int4,
    }
}

table! {
    users (id) {
        id -> Int4,
        usr -> Text,
        pwd -> Text,
    }
}

joinable!(scores -> users (usr_id));

allow_tables_to_appear_in_same_query!(
    scores,
    users,
);
