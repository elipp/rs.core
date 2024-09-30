#!/bin/bash

DATABASE_URL=postgres://auth:asd@127.0.0.1:5432/auth sqlx database setup
