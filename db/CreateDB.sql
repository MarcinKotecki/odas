-- Adminer 4.7.8 PostgreSQL dump

CREATE TABLE "public"."files" (
    "id" text NOT NULL,
    "value" bytea NOT NULL,
    "file_name" text NOT NULL,
    CONSTRAINT "files_id" PRIMARY KEY ("id")
) WITH (oids = false);


CREATE SEQUENCE login_attempts_id_seq INCREMENT 1 MINVALUE 1 MAXVALUE 9223372036854775807 START 55 CACHE 1;

CREATE TABLE "public"."login_attempts" (
    "user" text NOT NULL,
    "is_success" text NOT NULL,
    "ip" text NOT NULL,
    "time" numeric NOT NULL,
    "id" integer DEFAULT nextval('login_attempts_id_seq') NOT NULL,
    CONSTRAINT "login_attempts_id" PRIMARY KEY ("id")
) WITH (oids = false);


CREATE TABLE "public"."notes" (
    "id" text NOT NULL,
    "owner" text NOT NULL,
    "text" text NOT NULL,
    "is_public" text NOT NULL,
    "password" text NOT NULL,
    "creation_time" text NOT NULL,
    "file" text NOT NULL
) WITH (oids = false);


CREATE SEQUENCE sessions_id_seq INCREMENT 1 MINVALUE 1 MAXVALUE 2147483647 START 117 CACHE 1;

CREATE TABLE "public"."sessions" (
    "id" integer DEFAULT nextval('sessions_id_seq') NOT NULL,
    "session_id" character varying(255),
    "data" bytea,
    "expiry" timestamp,
    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "sessions_session_id_key" UNIQUE ("session_id")
) WITH (oids = false);


CREATE TABLE "public"."users" (
    "login" text NOT NULL,
    "password" text NOT NULL,
    "email" text NOT NULL
) WITH (oids = false);


-- 2021-01-14 20:17:12.620738+00
