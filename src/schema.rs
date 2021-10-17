table! {
    scores (id) {
        id -> Int4,
        usr_id -> Int4,
        score -> Int4,
        num_stars -> Int4,
    }
}

table! {
    users (id) {
        id -> Int4,
        usr -> Text,
        nickname -> Text,
        pwd -> Text,
        current_costume -> Text,
        costumes -> Array<Text>,
    }
}

joinable!(scores -> users (usr_id));

allow_tables_to_appear_in_same_query!(
    scores,
    users,
);
