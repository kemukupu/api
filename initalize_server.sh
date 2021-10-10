#!/bin/bash

until diesel migration run --locked-schema; do
  echo "Migrations failed, retrying in 5 seconds..."
  sleep 5
done

/app/target/release/api