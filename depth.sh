#!/usr/bin/env bash

for file in *.sqlite3; do
  sqlite3 --readonly "$file" "
    select 
      '$(basename "$file" .sqlite3)' as file,
       (select count(*) from response) as done,
       (select count(*) from fetch_queue) as fetch,
       (select count(*) from parse_queue) as parse
    group by file
    having fetch > 0
  "
done
