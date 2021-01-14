#!/bin/bash
if ! grep -q "SECRET_KEY=" ".env"; then
    key="$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)"
    echo -e "SECRET_KEY=${key}" >> .env
fi
if ! grep -q "POSTGRES_URI=" ".env"; then
    key="postgresql://dev:dev@db:5432/dev"
    echo -e "POSTGRES_URI=${key}" >> .env
fi
if ! grep -q "JWT_SECRET=" ".env"; then
    key="$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)"
    echo -e "JWT_SECRET=${key}" >> .env
fi
docker-compose up --build
