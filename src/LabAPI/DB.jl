"""
    DB

Mirrors `src/db.py`: SQLite registry for customers, vendors, and vendor orders. Schema is
reproduced byte-for-byte from the Python `CREATE TABLE` statements — this file must stay in
lockstep with `src/db.py`, not drift toward "idiomatic Julia."
"""
module DB

using SQLite
using ..Config: config

export init_db, init_vendors_db, insert_customer, insert_vendor, insert_vendor_order

const CUSTOMERS_DDL = raw"""
    CREATE TABLE IF NOT EXISTS customers (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_name TEXT NOT NULL UNIQUE CHECK(length(customer_name) >= 4 AND customer_name GLOB '[A-Z][a-z]*[A-Z][a-z]*'),
        iam_user_arn  TEXT NOT NULL CHECK(iam_user_arn LIKE 'arn:aws:iam::%:user/LabCustomer-%'),
        access_key_id TEXT NOT NULL CHECK(length(access_key_id) = 20 AND access_key_id GLOB '[A-Z]*'),
        bucket_name   TEXT NOT NULL CHECK(bucket_name LIKE 'research-%'),
        s3_prefix     TEXT NOT NULL CHECK(s3_prefix LIKE 'research-%/'),
        key_created   TEXT NOT NULL CHECK(key_created LIKE '____-__-__T%'),
        rotation_due  TEXT NOT NULL CHECK(rotation_due LIKE '____-__-__T%'),
        status        TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'rotating', 'suspended'))
    )
"""

const VENDORS_DDL = raw"""
    CREATE TABLE IF NOT EXISTS vendors (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor_name   TEXT NOT NULL UNIQUE CHECK(length(vendor_name) >= 2 AND vendor_name GLOB '[a-z0-9]*'),
        iam_user_arn  TEXT NOT NULL CHECK(iam_user_arn LIKE 'arn:aws:iam::%:user/LabVendor-%'),
        access_key_id TEXT NOT NULL CHECK(length(access_key_id) = 20 AND access_key_id GLOB '[A-Z]*'),
        bucket_name   TEXT NOT NULL CHECK(bucket_name LIKE 'caucell-%-landing'),
        key_created   TEXT NOT NULL CHECK(key_created LIKE '____-__-__T%'),
        rotation_due  TEXT NOT NULL CHECK(rotation_due LIKE '____-__-__T%'),
        status        TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'rotating', 'suspended'))
    )
"""

const VENDOR_ORDERS_DDL = raw"""
    CREATE TABLE IF NOT EXISTS vendor_orders (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id    TEXT NOT NULL UNIQUE CHECK(order_id GLOB '????????-????-????-????-????????????'),
        vendor_name TEXT NOT NULL,
        s3_prefix   TEXT NOT NULL CHECK(s3_prefix LIKE '%/'),
        created     TEXT NOT NULL CHECK(created LIKE '____-__-__T%'),
        status      TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'received', 'synced', 'closed')),
        notes       TEXT,
        FOREIGN KEY (vendor_name) REFERENCES vendors(vendor_name)
    )
"""

"""
    init_db() -> SQLite.DB

Idempotent. Creates `customers` in `config().db_path` if it doesn't exist and returns the
open handle — same contract as Python's `init_db()`.
"""
function init_db()
    db = SQLite.DB(config().db_path)
    SQLite.execute(db, CUSTOMERS_DDL)
    db
end

"""
    init_vendors_db() -> SQLite.DB

Idempotent. Creates `vendors` + `vendor_orders` (in the same DB file as `init_db()`) if they
don't exist. Independent of `init_db()` — each only touches its own tables, matching
`src/db.py`.
"""
function init_vendors_db()
    db = SQLite.DB(config().db_path)
    SQLite.execute(db, VENDORS_DDL)
    SQLite.execute(db, VENDOR_ORDERS_DDL)
    db
end

"""
    insert_customer(db, customer_name, iam_user_arn, access_key_id, bucket_name, s3_prefix,
                     key_created, rotation_due, status)

Column order matches the Python `INSERT INTO customers (...)` in `LabCustomersAPI.py`.
"""
function insert_customer(db, customer_name, iam_user_arn, access_key_id, bucket_name,
                          s3_prefix, key_created, rotation_due, status)
    SQLite.execute(db,
        """INSERT INTO customers
           (customer_name, iam_user_arn, access_key_id, bucket_name, s3_prefix, key_created, rotation_due, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (customer_name, iam_user_arn, access_key_id, bucket_name, s3_prefix, key_created, rotation_due, status))
end

"""
    insert_vendor(db, vendor_name, iam_user_arn, access_key_id, bucket_name, key_created,
                   rotation_due, status)

Column order matches the Python `INSERT INTO vendors (...)` in `LabVendorAPI.py`.
"""
function insert_vendor(db, vendor_name, iam_user_arn, access_key_id, bucket_name,
                        key_created, rotation_due, status)
    SQLite.execute(db,
        """INSERT INTO vendors
           (vendor_name, iam_user_arn, access_key_id, bucket_name, key_created, rotation_due, status)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (vendor_name, iam_user_arn, access_key_id, bucket_name, key_created, rotation_due, status))
end

"""
    insert_vendor_order(db, order_id, vendor_name, s3_prefix, created, status, notes)

Column order matches the Python `INSERT INTO vendor_orders (...)` in `LabVendorAPI.py`.
"""
function insert_vendor_order(db, order_id, vendor_name, s3_prefix, created, status, notes)
    SQLite.execute(db,
        """INSERT INTO vendor_orders (order_id, vendor_name, s3_prefix, created, status, notes)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (order_id, vendor_name, s3_prefix, created, status, notes))
end

end # module DB
