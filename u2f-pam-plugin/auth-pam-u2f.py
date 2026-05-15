#!/usr/bin/python3
# Copyright (C) 2026 SparkLabs Pty Ltd
#
# This file is part of OpenVPN U2F Server Support.
#
# OpenVPN U2F Server Support is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# OpenVPN U2F Server Support is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OpenVPN U2F Server Support.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import base64
import contextlib
import datetime
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import zlib

try:
    from fido2.ctap1 import RegistrationData, SignatureData
    from fido2.utils import sha256, websafe_decode, websafe_encode
except ImportError as import_error:
    RegistrationData = None
    SignatureData = None
    sha256 = None
    websafe_decode = None
    websafe_encode = None
    FIDO2_IMPORT_ERROR = import_error
else:
    FIDO2_IMPORT_ERROR = None


DEFAULT_CLIENT_NAME = "openvpn"
DEFAULT_DB_PATH = "/var/lib/openvpn-u2f-plugin/u2f.db"
LEGACY_U2FVAL_DB_PATH = "/etc/yubico/u2fval/u2fval.db"
DB_DIR_MODE = 0o700
DB_FILE_MODE = 0o600
TRANSACTION_TTL_SECONDS = 300
MAX_TRANSACTIONS_PER_USER = 5
MAX_CRV1_RESPONSE_JSON_BYTES = 16 * 1024


class U2FError(Exception):
    pass

def error(message):
    print(message, file=sys.stderr)

def require_fido2():
    if FIDO2_IMPORT_ERROR is not None:
        raise U2FError("python-fido2 is required: %s" % FIDO2_IMPORT_ERROR)

def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

def utcnow_string():
    return utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")

def parse_timestamp(value):
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.datetime.strptime(value, fmt)
        except ValueError:
            pass
    try:
        return datetime.datetime.fromisoformat(value.rstrip("Z"))
    except ValueError:
        return None

def base64encode_text(value):
    return base64.b64encode(value.encode("utf-8")).decode("ascii")

def crv1_response(prefix, username, payload):
    encoded_user = base64encode_text(username)
    encoded_payload = base64encode_text(json.dumps(payload, separators=(",", ":")))
    return "%s:%s:%s" % (prefix, encoded_user, encoded_payload)

def default_db_path():
    if os.path.exists(LEGACY_U2FVAL_DB_PATH):
        return LEGACY_U2FVAL_DB_PATH
    return DEFAULT_DB_PATH

def chmod_if_exists(path, mode):
    try:
        os.chmod(path, mode)
    except FileNotFoundError:
        pass

def restrict_database_permissions(db_path, suffixes):
    for suffix in suffixes:
        chmod_if_exists(db_path + suffix, DB_FILE_MODE)

def bounded_gzip_decompress(token):
    decompressor = zlib.decompressobj(47)
    try:
        token = decompressor.decompress(token, MAX_CRV1_RESPONSE_JSON_BYTES + 1)
    except zlib.error as exc:
        raise U2FError("Invalid U2F response compression") from exc

    if len(token) > MAX_CRV1_RESPONSE_JSON_BYTES or decompressor.unconsumed_tail:
        raise U2FError("U2F response is too large")

    remaining = MAX_CRV1_RESPONSE_JSON_BYTES - len(token)
    try:
        token += decompressor.flush(remaining + 1)
    except zlib.error as exc:
        raise U2FError("Invalid U2F response compression") from exc

    if len(token) > MAX_CRV1_RESPONSE_JSON_BYTES:
        raise U2FError("U2F response is too large")

    return token

def decode_crv1_password(password):
    if not password.startswith("CRV1:"):
        raise U2FError("Invalid U2F response prefix")

    parts = password.split("::", 2)
    if len(parts) != 3 or parts[0] != "CRV1":
        raise U2FError("Invalid U2F response format")

    mode = parts[1]
    try:
        token = base64.b64decode(parts[2].encode("ascii"))
    except Exception as exc:
        raise U2FError("Invalid U2F response encoding") from exc

    if token.startswith(b"\x1f\x8b"):
        token = bounded_gzip_decompress(token)

    if len(token) > MAX_CRV1_RESPONSE_JSON_BYTES:
        raise U2FError("U2F response is too large")

    try:
        response = json.loads(token.decode("utf-8"))
    except Exception as exc:
        raise U2FError("Invalid U2F response JSON") from exc

    if not isinstance(response, dict):
        raise U2FError("Invalid U2F response JSON")

    return mode, response

def decode_websafe(value, field_name):
    if not isinstance(value, str):
        raise U2FError("Missing or invalid %s" % field_name)
    try:
        return websafe_decode(value)
    except Exception as exc:
        raise U2FError("Invalid %s encoding" % field_name) from exc

def parse_client_data(response, expected_type):
    raw = decode_websafe(response.get("clientData"), "clientData")
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise U2FError("Invalid clientData JSON") from exc

    if data.get("typ") != expected_type:
        raise U2FError("Invalid clientData type")
    if not isinstance(data.get("challenge"), str):
        raise U2FError("Missing clientData challenge")
    if not isinstance(data.get("origin"), str):
        raise U2FError("Missing clientData origin")

    return raw, data

def normalize_origin(value):
    if not isinstance(value, str):
        return ""
    if value.endswith("/"):
        return value[:-1]
    return value

def parse_facets(value, app_id):
    facets = []
    if value:
        try:
            loaded = json.loads(value)
        except json.JSONDecodeError:
            loaded = [part.strip() for part in value.split(",")]
        if isinstance(loaded, list):
            facets = [item for item in loaded if isinstance(item, str) and item]

    if app_id not in facets:
        facets.append(app_id)
    return facets

def verify_origin(origin, facets):
    normalized_origin = normalize_origin(origin)
    normalized_facets = {normalize_origin(facet) for facet in facets}
    if normalized_origin not in normalized_facets:
        raise U2FError("U2F response origin is not trusted")

def transaction_id_for_challenge(challenge):
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()

def random_challenge():
    return websafe_encode(secrets.token_bytes(32))

def is_truthy(value):
    if value is None:
        return False
    if isinstance(value, int):
        return value != 0
    return str(value).lower() in ("1", "true", "yes")

class U2FStore:
    def __init__(self, db_path=None, app_id=None, valid_facets=None):
        self.db_path = db_path or os.environ.get("OPENVPN_FIDO_DB_PATH") or default_db_path()
        self.client_name = DEFAULT_CLIENT_NAME
        self.app_id = app_id or os.environ.get("OPENVPN_FIDO_APP_ID")
        self.valid_facets = valid_facets or os.environ.get("OPENVPN_FIDO_VALID_FACETS")
        self.transaction_ttl = int(
            os.environ.get("OPENVPN_FIDO_TRANSACTION_TTL_SECONDS", TRANSACTION_TTL_SECONDS)
        )
        self.max_transactions = int(
            os.environ.get("OPENVPN_FIDO_MAX_TRANSACTIONS", MAX_TRANSACTIONS_PER_USER)
        )

    def connect(self):
        if not os.path.exists(self.db_path) and not self.app_id:
            message = "No existing U2F database found at %s" % self.db_path
            message += "; set OPENVPN_FIDO_APP_ID to initialize a new database"
            raise U2FError(message)

        parent = os.path.dirname(self.db_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, mode=DB_DIR_MODE, exist_ok=True)
            os.chmod(parent, DB_DIR_MODE)

        db_existed = os.path.exists(self.db_path)
        conn = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
        if not db_existed:
            restrict_database_permissions(self.db_path, ("",))

        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            pass
        if not db_existed:
            restrict_database_permissions(self.db_path, ("-wal", "-shm"))
        return conn

    @contextlib.contextmanager
    def transaction(self):
        conn = self.connect()
        try:
            self.ensure_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def ensure_schema(self, conn):
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER NOT NULL,
                name VARCHAR(40) NOT NULL,
                app_id VARCHAR(256) NOT NULL,
                valid_facets TEXT,
                PRIMARY KEY (id),
                UNIQUE (name)
            );
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER NOT NULL,
                fingerprint VARCHAR(128) NOT NULL,
                der TEXT NOT NULL,
                PRIMARY KEY (id),
                UNIQUE (fingerprint)
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER NOT NULL,
                name VARCHAR(40) NOT NULL,
                client_id INTEGER,
                PRIMARY KEY (id),
                CONSTRAINT _client_user_uc UNIQUE (client_id, name),
                FOREIGN KEY(client_id) REFERENCES clients (id)
            );
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER NOT NULL,
                handle VARCHAR(32) NOT NULL,
                user_id INTEGER,
                bind_data TEXT,
                certificate_id INTEGER,
                compromised BOOLEAN,
                created_at DATETIME,
                authenticated_at DATETIME,
                counter BIGINT,
                transports BIGINT,
                PRIMARY KEY (id),
                UNIQUE (handle),
                FOREIGN KEY(user_id) REFERENCES users (id),
                FOREIGN KEY(certificate_id) REFERENCES certificates (id)
            );
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER NOT NULL,
                user_id INTEGER,
                transaction_id VARCHAR(64) NOT NULL,
                _data TEXT,
                created_at DATETIME,
                PRIMARY KEY (id),
                FOREIGN KEY(user_id) REFERENCES users (id),
                UNIQUE (transaction_id)
            );
            CREATE TABLE IF NOT EXISTS properties (
                id INTEGER NOT NULL,
                "key" VARCHAR(40),
                value TEXT,
                device_id INTEGER,
                PRIMARY KEY (id),
                FOREIGN KEY(device_id) REFERENCES devices (id)
            );
            """
        )

    def get_client(self, conn, create):
        row = conn.execute("SELECT * FROM clients WHERE name = ?", (self.client_name,)).fetchone()
        if row is not None:
            return row

        if not create or not self.app_id:
            raise U2FError(
                "No U2F client named openvpn found; set OPENVPN_FIDO_APP_ID to initialize it"
            )

        facets = self.valid_facets or json.dumps([self.app_id])
        cur = conn.execute(
            "INSERT INTO clients (name, app_id, valid_facets) VALUES (?, ?, ?)",
            (self.client_name, self.app_id, facets),
        )
        return conn.execute("SELECT * FROM clients WHERE id = ?", (cur.lastrowid,)).fetchone()

    def get_user(self, conn, client_id, username):
        return conn.execute(
            "SELECT * FROM users WHERE client_id = ? AND name = ?", (client_id, username)
        ).fetchone()

    def get_or_create_user(self, conn, client_id, username):
        row = self.get_user(conn, client_id, username)
        if row is not None:
            return row

        cur = conn.execute(
            "INSERT INTO users (name, client_id) VALUES (?, ?)", (username, client_id)
        )
        return conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()

    def device_count(self, conn, user_id):
        row = conn.execute(
            "SELECT COUNT(*) AS count FROM devices WHERE user_id = ?", (user_id,)
        ).fetchone()
        return int(row["count"])

    def usable_devices(self, conn, user_id):
        rows = conn.execute(
            """
            SELECT *
              FROM devices
             WHERE user_id = ? AND (compromised IS NULL OR compromised = 0)
             ORDER BY id
            """,
            (user_id,),
        ).fetchall()
        return [row for row in rows if self.load_bind_data(row) is not None]

    def load_bind_data(self, device):
        try:
            data = json.loads(device["bind_data"])
        except Exception:
            return None
        required = ("version", "keyHandle", "publicKey", "appId")
        if not all(isinstance(data.get(key), str) for key in required):
            return None
        return data

    def client_context(self, client):
        app_id = client["app_id"]
        return app_id, parse_facets(client["valid_facets"], app_id)

    def cleanup_transactions(self, conn, user_id):
        cutoff = (utcnow() - datetime.timedelta(seconds=self.transaction_ttl)).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )
        conn.execute(
            "DELETE FROM transactions WHERE user_id = ? AND created_at < ?", (user_id, cutoff)
        )

        rows = conn.execute(
            "SELECT id FROM transactions WHERE user_id = ? ORDER BY created_at DESC, id DESC",
            (user_id,),
        ).fetchall()
        for row in rows[self.max_transactions :]:
            conn.execute("DELETE FROM transactions WHERE id = ?", (row["id"],))

    def store_transaction(self, conn, user_id, data):
        self.cleanup_transactions(conn, user_id)

        for _ in range(5):
            challenge = random_challenge()
            stored = dict(data)
            stored["challenge"] = challenge
            try:
                conn.execute(
                    """
                    INSERT INTO transactions (user_id, transaction_id, _data, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        transaction_id_for_challenge(challenge),
                        json.dumps(stored, separators=(",", ":")),
                        utcnow_string(),
                    ),
                )
                return stored
            except sqlite3.IntegrityError:
                pass

        raise U2FError("Unable to create a unique U2F challenge")

    def consume_transaction(self, conn, user_id, challenge, expected_type):
        row = conn.execute(
            """
            SELECT *
              FROM transactions
             WHERE user_id = ? AND transaction_id = ?
            """,
            (user_id, transaction_id_for_challenge(challenge)),
        ).fetchone()
        if row is None:
            raise U2FError("U2F challenge not found")

        conn.execute("DELETE FROM transactions WHERE id = ?", (row["id"],))

        created_at = parse_timestamp(row["created_at"])
        if created_at is None or utcnow() - created_at > datetime.timedelta(
            seconds=self.transaction_ttl
        ):
            raise U2FError("U2F challenge has expired")

        try:
            data = json.loads(row["_data"])
        except Exception as exc:
            raise U2FError("Stored U2F challenge is invalid") from exc

        if data.get("type") != expected_type or data.get("challenge") != challenge:
            raise U2FError("Stored U2F challenge does not match response")
        return data

    def certificate_id(self, conn, der):
        fingerprint = hashlib.sha256(der).hexdigest()
        row = conn.execute(
            "SELECT id FROM certificates WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if row is not None:
            return row["id"]

        cur = conn.execute(
            "INSERT INTO certificates (fingerprint, der) VALUES (?, ?)",
            (fingerprint, base64.b64encode(der).decode("ascii")),
        )
        return cur.lastrowid

    def insert_device(self, conn, user_id, bind_data, certificate_id):
        for _ in range(5):
            handle = secrets.token_hex(16)
            try:
                conn.execute(
                    """
                    INSERT INTO devices
                        (handle, user_id, bind_data, certificate_id, compromised,
                         created_at, authenticated_at, counter, transports)
                    VALUES (?, ?, ?, ?, 0, ?, NULL, NULL, 0)
                    """,
                    (
                        handle,
                        user_id,
                        json.dumps(bind_data, separators=(",", ":")),
                        certificate_id,
                        utcnow_string(),
                    ),
                )
                return
            except sqlite3.IntegrityError:
                pass

        raise U2FError("Unable to create a unique U2F device handle")

    def mark_compromised(self, conn, device_id):
        conn.execute("UPDATE devices SET compromised = 1 WHERE id = ?", (device_id,))

    def update_counter(self, conn, device_id, counter):
        cur = conn.execute(
            """
            UPDATE devices
               SET counter = ?, authenticated_at = ?
             WHERE id = ? AND (counter IS NULL OR counter < ?)
            """,
            (counter, utcnow_string(), device_id, counter),
        )
        return cur.rowcount == 1

    def reset_user_devices(self, username):
        with self.transaction() as conn:
            client = self.get_client(conn, create=False)
            user = self.get_user(conn, client["id"], username)
            if user is None:
                raise U2FError("No U2F user named %s exists" % username)

            user_id = user["id"]
            devices = conn.execute(
                "SELECT id FROM devices WHERE user_id = ? ORDER BY id", (user_id,)
            ).fetchall()
            device_ids = [row["id"] for row in devices]

            tx_cursor = conn.execute(
                "DELETE FROM transactions WHERE user_id = ?", (user_id,)
            )
            property_count = 0
            if device_ids:
                placeholders = ",".join("?" for _ in device_ids)
                property_cursor = conn.execute(
                    "DELETE FROM properties WHERE device_id IN (%s)" % placeholders,
                    device_ids,
                )
                property_count = property_cursor.rowcount

            device_cursor = conn.execute("DELETE FROM devices WHERE user_id = ?", (user_id,))
            return {
                "username": username,
                "client": client["name"],
                "devices": device_cursor.rowcount,
                "properties": property_count,
                "transactions": tx_cursor.rowcount,
            }

class OpenVPNU2FAuthPlugin:
    def __init__(self):
        require_fido2()
        self.store = U2FStore()

    def run(self):
        username = os.environ.get("username")
        password = os.environ.get("password")

        if not username:
            raise U2FError("No username issued")

        if password is None:
            print(self.begin(username))
            return 2

        mode, response = decode_crv1_password(password)
        if mode == "reg" or "registrationData" in response:
            self.finish_registration(username, response)
            print(self.build_authentication(username))
            return 2

        if mode == "auth" or "signatureData" in response:
            self.finish_authentication(username, response)
            return 0

        raise U2FError("Unknown U2F response mode")

    def begin(self, username):
        with self.store.transaction() as conn:
            client = self.store.get_client(conn, create=True)
            user = self.store.get_or_create_user(conn, client["id"], username)
            if self.store.device_count(conn, user["id"]) == 0:
                return self.build_registration_locked(conn, client, user)
        return self.build_authentication(username)

    def build_registration_locked(self, conn, client, user):
        app_id, facets = self.store.client_context(client)
        transaction = self.store.store_transaction(
            conn,
            user["id"],
            {
                "type": "registration",
                "appId": app_id,
                "validFacets": facets,
            },
        )
        request = {
            "challenge": transaction["challenge"],
            "version": "U2F_V2",
            "appId": app_id,
        }
        return crv1_response("CRV1:U2F,R:reg", user["name"], request)

    def build_authentication(self, username):
        with self.store.transaction() as conn:
            client = self.store.get_client(conn, create=False)
            user = self.store.get_user(conn, client["id"], username)
            if user is None:
                raise U2FError("U2F user is not registered")

            devices = self.store.usable_devices(conn, user["id"])
            if not devices:
                raise U2FError("No usable U2F devices are registered")

            device = devices[0]
            bind_data = self.store.load_bind_data(device)
            app_id, facets = self.store.client_context(client)
            transaction = self.store.store_transaction(
                conn,
                user["id"],
                {
                    "type": "authentication",
                    "appId": app_id,
                    "validFacets": facets,
                    "deviceHandle": device["handle"],
                    "keyHandle": bind_data["keyHandle"],
                },
            )
            request = {
                "challenge": transaction["challenge"],
                "appId": app_id,
                "keyHandle": bind_data["keyHandle"],
                "version": bind_data["version"],
            }
            return crv1_response("CRV1:U2F:auth", username, request)

    def finish_registration(self, username, response):
        client_data_raw, client_data = parse_client_data(
            response, "navigator.id.finishEnrollment"
        )
        challenge = client_data["challenge"]

        with self.store.transaction() as conn:
            client = self.store.get_client(conn, create=False)
            user = self.store.get_user(conn, client["id"], username)
            if user is None:
                raise U2FError("U2F user is not registered")

            transaction = self.store.consume_transaction(
                conn, user["id"], challenge, "registration"
            )
            user_id = user["id"]

        app_id = transaction["appId"]
        facets = transaction["validFacets"]
        verify_origin(client_data["origin"], facets)

        registration_data = RegistrationData(
            decode_websafe(response.get("registrationData"), "registrationData")
        )
        registration_data.verify(sha256(app_id.encode("utf-8")), sha256(client_data_raw))

        bind_data = {
            "version": response.get("version", "U2F_V2"),
            "keyHandle": websafe_encode(registration_data.key_handle),
            "publicKey": websafe_encode(registration_data.public_key),
            "appId": app_id,
        }
        if bind_data["version"] != "U2F_V2":
            raise U2FError("Unsupported U2F registration version")

        with self.store.transaction() as conn:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if user is None:
                raise U2FError("U2F user is not registered")
            if self.store.device_count(conn, user["id"]) != 0:
                raise U2FError("U2F user already has a registered device")

            certificate_id = self.store.certificate_id(conn, registration_data.certificate)
            self.store.insert_device(conn, user["id"], bind_data, certificate_id)

    def finish_authentication(self, username, response):
        client_data_raw, client_data = parse_client_data(response, "navigator.id.getAssertion")
        challenge = client_data["challenge"]

        with self.store.transaction() as conn:
            client = self.store.get_client(conn, create=False)
            user = self.store.get_user(conn, client["id"], username)
            if user is None:
                raise U2FError("U2F user is not registered")

            transaction = self.store.consume_transaction(
                conn, user["id"], challenge, "authentication"
            )
            user_id = user["id"]
            device = conn.execute(
                """
                SELECT *
                  FROM devices
                 WHERE user_id = ? AND handle = ?
                """,
                (user["id"], transaction["deviceHandle"]),
            ).fetchone()
            if device is None:
                raise U2FError("U2F device not found")
            if is_truthy(device["compromised"]):
                raise U2FError("U2F device has been marked compromised")

            bind_data = self.store.load_bind_data(device)
            if bind_data is None:
                raise U2FError("Stored U2F device data is invalid")
            device_id = device["id"]

        app_id = transaction["appId"]
        facets = transaction["validFacets"]
        verify_origin(client_data["origin"], facets)

        key_handle = response.get("keyHandle", transaction["keyHandle"])
        if key_handle != transaction["keyHandle"] or bind_data["keyHandle"] != key_handle:
            raise U2FError("U2F response used an unexpected key handle")

        signature_data = SignatureData(
            decode_websafe(response.get("signatureData"), "signatureData")
        )
        if (signature_data.user_presence & 0x01) != 0x01:
            raise U2FError("U2F response does not assert user presence")

        public_key = decode_websafe(bind_data["publicKey"], "publicKey")
        signature_data.verify(
            sha256(app_id.encode("utf-8")), sha256(client_data_raw), public_key
        )

        with self.store.transaction() as conn:
            device = conn.execute(
                """
                SELECT *
                  FROM devices
                 WHERE id = ? AND user_id = ?
                """,
                (device_id, user_id),
            ).fetchone()
            if device is None:
                raise U2FError("U2F device not found")
            if is_truthy(device["compromised"]):
                raise U2FError("U2F device has been marked compromised")

            latest_bind_data = self.store.load_bind_data(device)
            if latest_bind_data is None or latest_bind_data["keyHandle"] != key_handle:
                raise U2FError("Stored U2F device data is invalid")

            if not self.store.update_counter(conn, device["id"], signature_data.counter):
                self.store.mark_compromised(conn, device["id"])
                raise U2FError("U2F device counter did not increase")

def main():
    try:
        if len(sys.argv) > 1:
            return run_admin_command(sys.argv[1:])
        return OpenVPNU2FAuthPlugin().run()
    except U2FError as exc:
        error(str(exc))
    except Exception as exc:
        error("Unexpected U2F authentication error: %s" % exc)
    return 1

def run_admin_command(argv):
    parser = argparse.ArgumentParser(
        description="OpenVPN U2F helper and local credential store utility"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    reset_parser = subparsers.add_parser(
        "reset-devices",
        help="Remove a user's registered U2F devices and pending challenges",
    )
    reset_parser.add_argument(
        "--db",
        default=os.environ.get("OPENVPN_FIDO_DB_PATH") or default_db_path(),
        help="Path to the U2F SQLite database",
    )
    reset_parser.add_argument("username", help="Username to reset")

    args = parser.parse_args(argv)
    store = U2FStore(db_path=args.db)

    if args.command == "reset-devices":
        result = store.reset_user_devices(args.username)
        print(
            "Reset U2F user %(username)s for client %(client)s: "
            "%(devices)s device(s), %(properties)s device property record(s), "
            "%(transactions)s pending challenge(s) removed" % result
        )
        return 0

    parser.error("Unknown command")
    return 2

if __name__ == "__main__":
    sys.exit(main())
