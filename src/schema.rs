table! {
    scores (id) {
        id -> Int4,
        usr_id -> Int4,
        score -> Int4,
    }
}

table! {
    shares (id) {
        id -> Int8,
        public_id -> Text,
        created_at -> Nullable<Timestamptz>,
        expires -> Nullable<Timestamptz>,
        usr -> Text,
        website -> Bool,
        wget -> Bool,
        name -> Text,
        size -> Int8,
        file_type -> Text,
    }
}

table! {
    users (id) {
        id -> Int4,
        usr -> Text,
        pwd -> Text,
    }
}

allow_tables_to_appear_in_same_query!(
    scores,
    shares,
    users,
);
