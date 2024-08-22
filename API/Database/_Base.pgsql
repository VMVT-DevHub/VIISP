

-- DB Setup

DO LANGUAGE 'plpgsql' $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rairai'        ) THEN CREATE ROLE rairai; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'apps'          ) THEN CREATE ROLE apps; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '_master_admin' ) THEN CREATE ROLE _master_admin; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'viisp_app'     ) THEN CREATE ROLE viisp_app WITH LOGIN INHERIT CONNECTION LIMIT -1 PASSWORD 'viisp_app'; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'master'     ) THEN CREATE DATABASE master WITH OWNER = _master_admin ENCODING = 'UTF8' CONNECTION LIMIT = -1; END IF;
    GRANT apps TO viisp_app;
    GRANT CONNECT ON DATABASE master TO viisp_app;
    GRANT ALL ON DATABASE master TO _master_admin;
END $$;

-- Schema Setup

DO LANGUAGE 'plpgsql' $$ BEGIN
    CREATE SCHEMA IF NOT EXISTS viisp AUTHORIZATION _master_admin;
    SET SESSION AUTHORIZATION _master_admin;
    GRANT USAGE ON SCHEMA viisp TO viisp_app;
    GRANT ALL ON SCHEMA viisp TO _master_admin;
    ALTER DEFAULT PRIVILEGES FOR ROLE _master_admin IN SCHEMA viisp GRANT ALL ON TABLES TO _master_admin WITH GRANT OPTION;
    ALTER DEFAULT PRIVILEGES FOR ROLE _master_admin IN SCHEMA viisp GRANT ALL ON TABLES TO viisp_app;
END $$;


-- Tables

CREATE TABLE IF NOT EXISTS viisp.users (
    user_id uuid NOT NULL DEFAULT gen_random_uuid(), user_ak bigint NOT NULL,
    user_name varchar(255) NOT NULL, user_fname varchar(255) NOT NULL, user_lname varchar(255) NOT NULL,
    user_address varchar(255), user_email varchar(255), user_phone varchar(30), user_country varchar(30),
    user_dt_add timestamp(0) NOT NULL DEFAULT timezone('utc'::text, now()), user_dt_modif timestamp(3) without time zone,
    CONSTRAINT viisp_users_pk PRIMARY KEY (user_id), CONSTRAINT viisp_users_ak UNIQUE (user_ak)
);
CREATE INDEX viisp_users_ak_idx on viisp.users (user_ak);

CREATE TABLE IF NOT EXISTS viisp.log_logins (
    log_id bigint NOT NULL GENERATED ALWAYS AS IDENTITY, log_app varchar(12) NOT NULL, log_user uuid NOT NULL,
    log_jar bigint, log_date timestamp(3) NOT NULL DEFAULT timezone('utc'::text, now()),
    log_ip varchar(255), log_ua text, log_data jsonb, CONSTRAINT viisp_log_logins_pk PRIMARY KEY (log_id)
);
CREATE INDEX viisp_log_logins_app_idx on viisp.log_logins (log_app);
CREATE INDEX viisp_log_logins_user_idx on viisp.log_logins (log_user);

CREATE TABLE IF NOT EXISTS viisp.log_modif (
    log_id bigint NOT NULL GENERATED ALWAYS AS IDENTITY, log_user uuid NOT NULL, log_action varchar(12),
    log_date timestamp(3) NOT NULL DEFAULT timezone('utc'::text, now()), log_data jsonb, CONSTRAINT viisp_log_modif_pk PRIMARY KEY (log_id)
); CREATE INDEX viisp_log_modif_user_idx on viisp.log_modif (log_user);

-- Triggers

CREATE OR REPLACE FUNCTION viisp.users_trg() RETURNS trigger LANGUAGE 'plpgsql' AS $BODY$
DECLARE gid varchar(255); adr varchar(255); chng jsonb; BEGIN 
    NEW.user_dt_modif = timezone('utc'::text, now());
    chng=viisp.log_change(chng,'name',NEW.user_name,OLD.user_name);
    chng=viisp.log_change(chng,'lname',NEW.user_lname,OLD.user_lname);
    chng=viisp.log_change(chng,'fname',NEW.user_fname,OLD.user_fname);
    chng=viisp.log_change(chng,'address',NEW.user_address,OLD.user_address);
    chng=viisp.log_change(chng,'email',NEW.user_email,OLD.user_email);
    chng=viisp.log_change(chng,'phone',NEW.user_phone,OLD.user_phone);
    chng=viisp.log_change(chng,'country',NEW.user_country,OLD.user_country);
    IF TG_OP = 'INSERT' THEN NEW.user_id = gen_random_uuid(); INSERT INTO viisp.log_modif (log_user,log_action,log_data) VALUES (NEW.user_id,'New',chng);
    ELSIF TG_OP = 'UPDATE' THEN
        IF OLD.user_id<>NEW.user_id THEN RAISE EXCEPTION 'ID keitimas negalimas'; END IF;
        IF OLD.user_ak<>NEW.user_ak THEN RAISE EXCEPTION 'AK keitimas negalimas'; END IF;
        INSERT INTO viisp.log_modif (log_user,log_action,log_data) VALUES (NEW.user_id,'Update',chng);
    ELSE RAISE EXCEPTION 'Netinkamas veiksmas'; END IF; RETURN NEW;
END; $BODY$;
CREATE TRIGGER viisp_users BEFORE INSERT OR DELETE OR UPDATE ON viisp.users FOR EACH ROW EXECUTE FUNCTION viisp.users_trg();



-- Functions

CREATE OR REPLACE FUNCTION viisp.log_change(obj jsonb, title varchar, vnew anyelement, vold anyelement) RETURNS jsonb LANGUAGE 'plpgsql' AS $BODY$ BEGIN
    IF obj is null THEN obj:=jsonb_build_object(); END IF; IF COALESCE(vold::text,'')<>COALESCE(vnew::text,'') THEN 
    RETURN obj || jsonb_build_object(title, jsonb_build_array(vold,vnew)); ELSE RETURN obj; END IF; END $BODY$;

CREATE OR REPLACE FUNCTION viisp.user_login(ak bigint, app varchar, ip varchar, ua text, dt jsonb)
    RETURNS TABLE(id uuid, name varchar, fname varchar, lname varchar, address varchar, email varchar, phone varchar, country varchar) LANGUAGE 'plpgsql' AS $BODY$ 
    DECLARE uid uuid; jar bigint; jst varchar=dt->>'lt-company-code'; BEGIN
    SELECT user_id into uid FROM viisp.users WHERE user_ak=ak;
    IF uid is not null THEN
        UPDATE viisp.users SET user_name=COALESCE(dt->>'name',''), user_fname=COALESCE(dt->>'firstName',''), user_lname=COALESCE(dt->>'lastName',''), user_address=dt->>'address', user_phone=dt->>'phoneNumber', user_email=dt->>'email', user_country=dt->>'country'
        WHERE user_id=uid AND ((dt->>'name' is not null AND dt->>'name'<>user_name) OR (dt->>'firstName' is not null AND dt->>'firstName'<>user_fname) OR (dt->>'lastName' is not null AND dt->>'lastName'<>user_lname) OR 
            (dt->>'address' is not null AND dt->>'address'<>user_address) OR (dt->>'phoneNumber' is not null AND dt->>'phoneNumber'<>user_phone) OR (dt->>'email' is not null AND dt->>'email'<>user_email) OR (dt->>'country' is not null AND dt->>'country'<>user_country));
    ELSE INSERT INTO viisp.users (user_ak,user_name,user_fname,user_lname,user_address,user_phone,user_email,user_country) VALUES 
            (ak,COALESCE(dt->>'name',''),COALESCE(dt->>'firstName',''),COALESCE(dt->>'lastName',''),dt->>'address',dt->>'phoneNumber',dt->>'email',dt->>'country') RETURNING user_id INTO uid;
    END IF; IF COALESCE(jst,'') <> '' AND jst ~ '^[0-9]+$' THEN jar:=CAST(jst AS bigint); END IF;
    INSERT INTO viisp.log_logins (log_app,log_user,log_jar,log_ip,log_ua,log_data) VALUES (app,uid,jar,ip,ua,dt);
    RETURN QUERY SELECT user_id, user_name, user_fname, user_lname, user_address, user_email, user_phone, user_country FROM viisp.users WHERE user_id=uid;
END $BODY$;

