# Re-authors tests/test_vendor_db.py against DB.jl (vendors + vendor_orders CHECK DDL).

const VALID_VENDOR = (
    vendor_name   = "genewiz",
    iam_user_arn  = "arn:aws:iam::123456789012:user/LabVendor-genewiz",
    access_key_id = "AKIAIOSFODNN7EXAMPLE",
    bucket_name   = "caucell-genewiz-landing",
    key_created   = "2025-01-01T00:00:00+00:00",
    rotation_due  = "2025-04-01T00:00:00+00:00",
    status        = "active",
)

const VALID_ORDER = (
    order_id    = "12345678-1234-1234-1234-123456789abc",
    vendor_name = "genewiz",
    s3_prefix   = "12345678-1234-1234-1234-123456789abc/",
    created     = "2025-01-01T00:00:00+00:00",
    status      = "open",
    notes       = missing,
)

function ins_vendor(db, overrides = (;))
    r = merge(VALID_VENDOR, overrides)
    insert_vendor(db, r.vendor_name, r.iam_user_arn, r.access_key_id, r.bucket_name,
                  r.key_created, r.rotation_due, r.status)
end

function ins_order(db, overrides = (;))
    r = merge(VALID_ORDER, overrides)
    insert_vendor_order(db, r.order_id, r.vendor_name, r.s3_prefix, r.created, r.status, r.notes)
end

@testset "DB vendors" begin
    @testset "init_vendors_db creates both tables + idempotent" begin
        withdb() do
            db = init_vendors_db()
            tables = Set(row.name for row in
                         SQLite.DBInterface.execute(db, "SELECT name FROM sqlite_master WHERE type='table'"))
            close(db)
            @test "vendors" in tables
            @test "vendor_orders" in tables
            close(init_vendors_db())
        end
    end

    @testset "vendor happy path + default status" begin
        withdb() do
            db = init_vendors_db()
            ins_vendor(db)
            row = [NamedTuple(r) for r in
                   SQLite.DBInterface.execute(db, "SELECT * FROM vendors WHERE vendor_name='genewiz'")][1]
            @test row.bucket_name == "caucell-genewiz-landing"
            close(db)
        end
        withdb() do
            db = init_vendors_db()
            SQLite.execute(db,
                """INSERT INTO vendors
                   (vendor_name, iam_user_arn, access_key_id, bucket_name, key_created, rotation_due)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (VALID_VENDOR.vendor_name, VALID_VENDOR.iam_user_arn, VALID_VENDOR.access_key_id,
                 VALID_VENDOR.bucket_name, VALID_VENDOR.key_created, VALID_VENDOR.rotation_due))
            r = [NamedTuple(x) for x in SQLite.DBInterface.execute(db, "SELECT status FROM vendors")][1]
            close(db)
            @test r.status == "active"
        end
    end

    @testset "vendor CHECK constraints" begin
        withdb() do
            db = init_vendors_db()
            ins_vendor(db)
            @test threw(() -> ins_vendor(db, (access_key_id = "BKIAIOSFODNN7EXAMPLE",)))  # dup name
            close(db)
        end
        for (label, ov) in [
            ("uppercase name",  (vendor_name = "GeneWiz",)),
            ("too-short name",  (vendor_name = "g",)),
            ("customer arn",    (iam_user_arn = "arn:aws:iam::123456789012:user/LabCustomer-genewiz",)),
            ("short key",       (access_key_id = "SHORT",)),
            ("research bucket", (bucket_name = "research-genewiz",)),
            ("bad timestamp",   (key_created = "not-a-date",)),
            ("bad status",      (status = "deleted",)),
        ]
            withdb() do
                db = init_vendors_db()
                @test threw(() -> ins_vendor(db, ov)) == true  # $label
                close(db)
            end
        end
        withdb() do
            db = init_vendors_db()
            @test !threw(() -> ins_vendor(db, (status = "suspended",)))
            close(db)
        end
    end

    @testset "vendor_orders constraints" begin
        withdb() do
            db = init_vendors_db()
            ins_order(db)
            row = [NamedTuple(r) for r in
                   SQLite.DBInterface.execute(db, "SELECT * FROM vendor_orders")][1]
            @test row.status == "open"
            close(db)
        end
        # default status open (omit status column)
        withdb() do
            db = init_vendors_db()
            SQLite.execute(db,
                """INSERT INTO vendor_orders (order_id, vendor_name, s3_prefix, created, notes)
                   VALUES (?, ?, ?, ?, ?)""",
                (VALID_ORDER.order_id, VALID_ORDER.vendor_name, VALID_ORDER.s3_prefix,
                 VALID_ORDER.created, VALID_ORDER.notes))
            r = [NamedTuple(x) for x in SQLite.DBInterface.execute(db, "SELECT status FROM vendor_orders")][1]
            close(db)
            @test r.status == "open"
        end
        for (label, ov) in [
            ("bad uuid shape", (order_id = "not-a-uuid",)),
            ("prefix no slash", (s3_prefix = "12345678-1234-1234-1234-123456789abc",)),
            ("bad status",     (status = "cancelled",)),
        ]
            withdb() do
                db = init_vendors_db()
                @test threw(() -> ins_order(db, ov)) == true  # $label
                close(db)
            end
        end
        withdb() do
            db = init_vendors_db()
            ins_order(db)
            @test threw(() -> ins_order(db))  # duplicate order_id
            close(db)
        end
    end
end
