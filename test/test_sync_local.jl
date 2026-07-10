# Re-authors the offline half of tests/test_sync.py against Sync.jl. Manifests are
# `rel => (size, mtime)` NamedTuples (mirroring Python's {"size": n, "mtime": t} dicts);
# S3-side values are `key => (size, last_modified)` with last_modified in epoch seconds.

@testset "Sync (offline)" begin
    @testset "discover_nas_researchers" begin
        mktempdir() do d
            mkdir(joinpath(d, "JohnSmith")); mkdir(joinpath(d, "JaneDoe"))
            @test discover_nas_researchers(d) == ["JaneDoe", "JohnSmith"]
        end
        mktempdir() do d
            mkdir(joinpath(d, ".hidden")); mkdir(joinpath(d, "JohnSmith"))
            @test discover_nas_researchers(d) == ["JohnSmith"]
        end
        mktempdir() do d
            mkdir(joinpath(d, "Caucell")); mkdir(joinpath(d, "JohnSmith"))
            @test discover_nas_researchers(d) == ["JohnSmith"]
        end
        mktempdir() do d
            mkdir(joinpath(d, "lowercase")); mkdir(joinpath(d, "UPPERCASE")); mkdir(joinpath(d, "JohnSmith"))
            @test discover_nas_researchers(d) == ["JohnSmith"]
        end
        mktempdir() do d
            mkdir(joinpath(d, "JohnSmith")); write(joinpath(d, "JaneDoe"), "not a dir")
            @test discover_nas_researchers(d) == ["JohnSmith"]
        end
        @test_throws AppError discover_nas_researchers(joinpath(tempdir(), "nope-$(rand(UInt32))"))
        mktempdir() do d
            @test discover_nas_researchers(d) == String[]
        end
    end

    @testset "discover_nas_participants" begin
        # Participants live one level deeper, under `<nas>/Caucell/Data`.
        mktempdir() do d
            base = joinpath(d, "Caucell", "Data"); mkpath(base)
            mkdir(joinpath(base, "JohnSmith")); mkdir(joinpath(base, "JaneDoe"))
            # Top-level dirs (including a would-be researcher) are NOT participants.
            mkdir(joinpath(d, "TopLevel"))
            @test discover_nas_participants(d) == ["JaneDoe", "JohnSmith"]
        end
        # Same TitleCase / dotfile / non-dir filtering as researcher discovery.
        mktempdir() do d
            base = joinpath(d, "Caucell", "Data"); mkpath(base)
            mkdir(joinpath(base, ".hidden")); mkdir(joinpath(base, "lowercase"))
            mkdir(joinpath(base, "JohnSmith")); write(joinpath(base, "JaneDoe"), "not a dir")
            @test discover_nas_participants(d) == ["JohnSmith"]
        end
        # Missing `Caucell/Data` base raises (volume/path not present).
        mktempdir() do d
            @test_throws AppError discover_nas_participants(d)
        end
    end

    @testset "build_local_manifest" begin
        mktempdir() do d
            write(joinpath(d, "file1.txt"), "hello"); write(joinpath(d, "file2.txt"), "world!")
            m = build_local_manifest(d)
            @test m["file1.txt"].size == 5
            @test m["file2.txt"].size == 6
            @test m["file1.txt"].mtime ≈ mtime(joinpath(d, "file1.txt"))
        end
        mktempdir() do d
            write(joinpath(d, ".hidden"), "secret"); write(joinpath(d, "visible.txt"), "ok")
            m = build_local_manifest(d)
            @test !haskey(m, ".hidden")
            @test haskey(m, "visible.txt")
        end
        mktempdir() do d
            @test isempty(build_local_manifest(d))
        end
        mktempdir() do d
            deep = joinpath(d, "sub", "deep"); mkpath(deep); write(joinpath(deep, "file.txt"), "nested")
            m = build_local_manifest(d)
            @test haskey(m, joinpath("sub", "deep", "file.txt"))
        end
    end

    @testset "build_root_readme_local_manifest" begin
        mktempdir() do d
            write(joinpath(d, "README.md"), "hi")
            m = build_root_readme_local_manifest(d)
            @test collect(keys(m)) == ["README.md"]
            @test m["README.md"].size == 2
        end
        mktempdir() do d
            @test isempty(build_root_readme_local_manifest(d))
        end
        mktempdir() do d
            mkdir(joinpath(d, "Data")); write(joinpath(d, "Data", "README.md"), "nested")
            @test isempty(build_root_readme_local_manifest(d))
        end
    end

    @testset "build_researcher_keyset" begin
        # Files across managed prefixes map to full keys; root README is included when present.
        mktempdir() do d
            mkdir(joinpath(d, "Data")); write(joinpath(d, "Data", "a.txt"), "a")
            mkdir(joinpath(d, "Result")); mkdir(joinpath(d, "Result", "sub"))
            write(joinpath(d, "Result", "sub", "b.txt"), "b")
            write(joinpath(d, "README.md"), "# hi")
            ks = build_researcher_keyset(d)
            @test ks == Set(["Data/a.txt", "Result/sub/b.txt", "README.md"])
        end
        # No README on NAS → README.md is NOT in the keyset (so it reads as managed, not drift).
        mktempdir() do d
            mkdir(joinpath(d, "Data")); write(joinpath(d, "Data", "a.txt"), "a")
            @test build_researcher_keyset(d) == Set(["Data/a.txt"])
        end
        # Directories outside the managed prefixes are ignored.
        mktempdir() do d
            mkdir(joinpath(d, "Random")); write(joinpath(d, "Random", "x.txt"), "x")
            @test isempty(build_researcher_keyset(d))
        end
    end

    @testset "compute_sync_delta" begin
        t = 1.75e9  # arbitrary epoch base
        local_m(entries...) = Dict{String,LabAPI.Sync.LocalEntry}(
            k => (size=s, mtime=mt) for (k, s, mt) in entries)
        s3_m(entries...) = Dict{String,LabAPI.Sync.S3Entry}(
            k => (size=s, last_modified=lm) for (k, s, lm) in entries)

        # Missing from S3 → upload.
        @test compute_sync_delta(local_m(("a.txt", 5, t)), s3_m()) == ["a.txt"]
        # Size differs → upload (regardless of mtime).
        @test compute_sync_delta(local_m(("a.txt", 5, t)), s3_m(("Data/a.txt", 9, t + 100))) == ["a.txt"]
        # Same size, local NEWER → upload (the mtime branch).
        @test compute_sync_delta(local_m(("a.txt", 5, t + 10)), s3_m(("Data/a.txt", 5, t))) == ["a.txt"]
        # Same size, local NOT newer → skip (the accepted aws-s3-sync trade-off).
        @test isempty(compute_sync_delta(local_m(("a.txt", 5, t - 10)), s3_m(("Data/a.txt", 5, t))))
        @test isempty(compute_sync_delta(local_m(("a.txt", 5, t)), s3_m(("Data/a.txt", 5, t))))
        # Custom prefix keys the comparison.
        @test compute_sync_delta(local_m(("a.txt", 5, t)), s3_m(("Data/a.txt", 5, t)), "Result/") == ["a.txt"]
        @test isempty(compute_sync_delta(local_m(("a.txt", 5, t - 10)), s3_m(("Result/a.txt", 5, t)), "Result/"))
        # Empty local manifest → nothing to upload.
        @test isempty(compute_sync_delta(local_m(), s3_m(("Data/x", 1, t))))
    end

    @testset "progress files" begin
        withprogress() do d
            # Missing file → empty set.
            @test load_progress("JohnSmith") == Set{String}()

            # Round-trip through our own save/load.
            save_progress("JohnSmith", Set(["Data/b.txt", "Data/a.txt"]))
            @test load_progress("JohnSmith") == Set(["Data/a.txt", "Data/b.txt"])
            # Sorted array on disk (deterministic, matching Python's json.dump(sorted(...))).
            @test occursin("\"uploaded\"", read(joinpath(d, "JohnSmith.json"), String))

            # clear removes the file; clearing again is a no-op.
            clear_progress("JohnSmith")
            @test !isfile(joinpath(d, "JohnSmith.json"))
            clear_progress("JohnSmith")

            # CROSS-LANGUAGE fixture: byte-for-byte what Python's save_progress writes
            # (json.dump with default separators) must load identically here.
            write(joinpath(d, "PyWritten.json"), """{"uploaded": ["Data/x.txt", "Result/y.txt"]}""")
            @test load_progress("PyWritten") == Set(["Data/x.txt", "Result/y.txt"])

            # Legacy bare-list format (tolerated by both implementations).
            write(joinpath(d, "Legacy.json"), """["Data/old.txt"]""")
            @test load_progress("Legacy") == Set(["Data/old.txt"])

            # Corrupt JSON / wrong shape → empty set, not an exception.
            write(joinpath(d, "Corrupt.json"), "{not json")
            @test load_progress("Corrupt") == Set{String}()
            write(joinpath(d, "WrongShape.json"), """{"other": 1}""")
            @test load_progress("WrongShape") == Set{String}()

            # And the reverse direction: what we write must parse under Python's reader
            # schema — {"uploaded": [...]} with a JSON array of strings.
            save_progress("JlWritten", Set(["Data/z.txt"]))
            raw = read(joinpath(d, "JlWritten.json"), String)
            parsed = JSON3.read(raw)
            @test haskey(parsed, "uploaded")
            @test parsed["uploaded"] isa AbstractVector
            @test String(parsed["uploaded"][1]) == "Data/z.txt"
        end
    end
end
