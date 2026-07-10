# Re-authors tests/test_db.py against DB.jl — exercises the byte-for-byte CHECK-constraint DDL.

const VALID_ROW = (
    customer_name = "JohnSmith",
    iam_user_arn  = "arn:aws:iam::123456789012:user/LabCustomer-JohnSmith",
    access_key_id = "AKIAIOSFODNN7EXAMPLE",
    bucket_name   = "research-johnsmith",
    s3_prefix     = "research-johnsmith/",
    key_created   = "2025-01-01T00:00:00+00:00",
    rotation_due  = "2025-04-01T00:00:00+00:00",
    status        = "active",
)

function ins_customer(db, overrides = (;))
    r = merge(VALID_ROW, overrides)
    insert_customer(db, r.customer_name, r.iam_user_arn, r.access_key_id, r.bucket_name,
                    r.s3_prefix, r.key_created, r.rotation_due, r.status)
end

@testset "DB customers" begin
    @testset "init_db creates table + idempotent" begin
        withdb() do
            db = init_db()
            tables = [row.name for row in
                      SQLite.DBInterface.execute(db, "SELECT name FROM sqlite_master WHERE type='table'")]
            close(db)
            @test "customers" in tables
            close(init_db())  # second call must not error
        end
    end

    @testset "insert happy path" begin
        withdb() do
            db = init_db()
            ins_customer(db)
            rows = [NamedTuple(r) for r in
                    SQLite.DBInterface.execute(db, "SELECT * FROM customers WHERE customer_name='JohnSmith'")]
            close(db)
            @test rows[1].bucket_name == "research-johnsmith"
        end
    end

    @testset "status defaults to active" begin
        withdb() do
            db = init_db()
            SQLite.execute(db,
                """INSERT INTO customers
                   (customer_name, iam_user_arn, access_key_id, bucket_name, s3_prefix, key_created, rotation_due)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (VALID_ROW.customer_name, VALID_ROW.iam_user_arn, VALID_ROW.access_key_id,
                 VALID_ROW.bucket_name, VALID_ROW.s3_prefix, VALID_ROW.key_created, VALID_ROW.rotation_due))
            r = [NamedTuple(x) for x in SQLite.DBInterface.execute(db, "SELECT status FROM customers")][1]
            close(db)
            @test r.status == "active"
        end
    end

    @testset "duplicate customer_name rejected" begin
        withdb() do
            db = init_db()
            ins_customer(db)
            @test threw(() -> ins_customer(db, (access_key_id = "BKIAIOSFODNN7EXAMPLE",)))
            close(db)
        end
    end

    @testset "CHECK constraints reject bad rows" begin
        for (label, ov) in [
            ("lowercase name",  (customer_name = "johnsmith",)),
            ("too-short name",  (customer_name = "JoS",)),
            ("bad arn",         (iam_user_arn = "not-an-arn",)),
            ("short key",       (access_key_id = "SHORT",)),
            ("lowercase key",   (access_key_id = "akiaiosfodnn7example",)),
            ("bad bucket",      (bucket_name = "not-research",)),
            ("bad s3_prefix",   (s3_prefix = "bad-prefix/",)),
            ("bad timestamp",   (key_created = "not-a-date",)),
            ("bad status",      (status = "deleted",)),
        ]
            withdb() do
                db = init_db()
                @test threw(() -> ins_customer(db, ov)) == true  # $label
                close(db)
            end
        end
    end

    @testset "valid non-default statuses accepted" begin
        for ok in [(status = "rotating",), (status = "suspended",)]
            withdb() do
                db = init_db()
                @test !threw(() -> ins_customer(db, ok))
                close(db)
            end
        end
    end

    @testset "path-based iam_user_arn accepted (new bare username under /lab-customers/)" begin
        withdb() do
            db = init_db()
            @test !threw(() -> ins_customer(db, (
                customer_name = "JaneDoe",
                iam_user_arn  = "arn:aws:iam::123456789012:user/lab-customers/JaneDoe",
                bucket_name   = "research-janedoe",
                s3_prefix     = "research-janedoe/")))
            close(db)
        end
    end

    @testset "init_db migrates a pre-path DB to the relaxed CHECK" begin
        # A DB created before path usernames has the original single-LIKE CHECK that only
        # accepts LabCustomer-%. init_db() must detect the stale DDL and rebuild in place,
        # preserving existing rows, so new path-ARN inserts stop failing.
        old_ddl = raw"""
            CREATE TABLE customers (
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
        withdb() do
            seed = SQLite.DB(ENV["DB_PATH"])
            SQLite.execute(seed, old_ddl)
            ins_customer(seed)  # legacy LabCustomer- row, valid under the old CHECK
            close(seed)

            db = init_db()  # triggers _migrate_customers_check
            legacy = [NamedTuple(r) for r in
                      SQLite.DBInterface.execute(db, "SELECT * FROM customers WHERE customer_name='JohnSmith'")]
            @test length(legacy) == 1  # existing row survived the rebuild
            @test !threw(() -> ins_customer(db, (  # path ARN the old CHECK rejected now inserts
                customer_name = "JaneDoe",
                iam_user_arn  = "arn:aws:iam::123456789012:user/lab-customers/JaneDoe",
                bucket_name   = "research-janedoe",
                s3_prefix     = "research-janedoe/")))
            close(db)
        end
    end
end
