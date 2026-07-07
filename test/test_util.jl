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
