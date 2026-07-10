# Re-authors tests/test_util.py against Util.jl.

@testset "Util" begin
    @testset "validate_customer_name" begin
        @test validate_customer_name("JohnSmith") === nothing
        @test validate_customer_name("AaBb") === nothing
        for bad in ("johnsmith", "John Smith", "John123", "John", "JOHNSMITH", "")
            @test_throws AppError validate_customer_name(bad)
        end
    end

    @testset "validate_vendor_name" begin
        @test validate_vendor_name("genewiz") === nothing
        @test validate_vendor_name("illumina-cloud") === nothing
        for bad in ("GeneWiz", "gene_wiz", "Genewiz")
            @test_throws AppError validate_vendor_name(bad)
        end
    end

    @testset "fmt_size tiers + boundaries" begin
        @test fmt_size(512) == "0.5 KB"
        @test fmt_size(1024) == "1.0 KB"
        @test fmt_size(5 * 1024^2) == "5.0 MB"
        @test fmt_size(2 * 1024^3) == "2.0 GB"
        @test fmt_size(1024^2) == "1.0 MB"
        @test fmt_size(1024^3) == "1.0 GB"
    end

    @testset "ignore_not_found" begin
        @test ignore_not_found(() -> throw(ErrorException("404 Not Found"))) === nothing
        @test ignore_not_found(() -> throw(ErrorException("NoSuchBucket"))) === nothing
        @test ignore_not_found(() -> throw(ErrorException("NoSuchEntity: gone"))) === nothing
        @test_throws ErrorException ignore_not_found(() -> throw(ErrorException("something else")))
        @test ignore_not_found(() -> "ok") == "ok"
    end

    @testset "as_vector single-element collapse" begin
        @test as_vector([1, 2]) == [1, 2]
        @test as_vector(5) == [5]
    end

    @testset "xml_children / xml_scalar both XMLDict shapes" begin
        LD(p...) = Dict{Union{String,Symbol},Any}(p...)

        # Ordered-fallback shape (what the real ListVersionsResult / ListMultipartUploadsResult
        # parse to): every child element is a one-key dict inside a single "" vector.
        ordered = LD("" => Any[
            LD("Name" => "research-x"), LD("Prefix" => LD()), LD("MaxKeys" => "1000"),
            LD("IsTruncated" => "true"), LD("NextKeyMarker" => "k9"),
            LD("Version" => LD("Key" => "Archive/", "VersionId" => "v0")),
            LD("Version" => LD("Key" => "Data/Study GiHe0 GiHe1/x.html", "VersionId" => "v1")),
            LD("DeleteMarker" => LD("Key" => "Data/gone.txt", "VersionId" => "dm1")),
        ])
        vs = xml_children(ordered, "Version")
        @test length(vs) == 2
        @test [v["Key"] for v in vs] == ["Archive/", "Data/Study GiHe0 GiHe1/x.html"]
        @test length(xml_children(ordered, "DeleteMarker")) == 1
        @test isempty(xml_children(ordered, "Upload"))
        @test xml_scalar(ordered, "IsTruncated", "false") == "true"
        @test xml_scalar(ordered, "NextKeyMarker", "") == "k9"
        @test xml_scalar(ordered, "NextVersionIdMarker", "") == ""   # absent → default

        # Merged shape (what list_objects_v2 yields): siblings under the tag as a vector.
        merged = LD("IsTruncated" => "false",
                    "Version" => Any[LD("Key" => "a", "VersionId" => "va"),
                                     LD("Key" => "b", "VersionId" => "vb")])
        @test length(xml_children(merged, "Version")) == 2
        @test xml_scalar(merged, "IsTruncated", "x") == "false"

        # Single-element collapse (repeated element occurring exactly once → bare dict).
        single = LD("Version" => LD("Key" => "solo", "VersionId" => "vs"))
        @test [v["Key"] for v in xml_children(single, "Version")] == ["solo"]

        # Absent everything → empty children, default scalar.
        empty = LD("Name" => "research-x", "IsTruncated" => "false")
        @test isempty(xml_children(empty, "Version"))
        @test xml_scalar(empty, "NextKeyMarker", "none") == "none"
    end

    @testset "username_from_arn (bare last segment)" begin
        # new customer: bare username under the /lab-customers/ path
        @test username_from_arn("arn:aws:iam::123456789012:user/lab-customers/JohnSmith") == "JohnSmith"
        # legacy customer: name carries the prefix, no path
        @test username_from_arn("arn:aws:iam::123456789012:user/LabCustomer-JohnSmith") == "LabCustomer-JohnSmith"
        # vendor: unchanged
        @test username_from_arn("arn:aws:iam::123456789012:user/LabVendor-genewiz") == "LabVendor-genewiz"
    end

    @testset "print_secret prints key + banner" begin
        # redirect_stdout needs a real OS stream, not an in-memory IOBuffer — capture via a temp file.
        out = mktemp() do path, io
            redirect_stdout(io) do
                print_secret("JohnSmith", "AKIAIOSFODNN7EXAMPLE", "secretkey", "research-johnsmith")
            end
            flush(io)
            read(path, String)
        end
        @test occursin("ONE-TIME SECRET", out)
        @test occursin("AKIAIOSFODNN7EXAMPLE", out)
        @test occursin("research-johnsmith", out)
    end
end
