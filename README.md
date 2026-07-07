# LabCloud.jl

Julia port of the Lab Customers / Lab Vendors provisioning tools. Manages the full
lifecycle of:

- **Lab customers** — S3 research buckets with scoped IAM credentials, key rotation,
  policy re-application, deletion, and NAS→S3 sync (`LabCustomersAPI.jl`).
- **Lab vendors** — `caucell-{vendor}-landing` S3 buckets with scoped IAM credentials for
  inbound sequencing data, per-order `{uuid}/` prefixes, key rotation, and deletion
  (`LabVendorAPI.jl`).

Shared logic (config, DB, AWS provisioning, upload, sync, CLI helpers) lives under
`src/LabAPI/`.

## Requirements

- Julia 1.12.5 (see `Manifest.toml`)
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
  (used to configure credentials — the CLIs themselves talk to AWS via `AWS.jl`)
- AWS credentials for the `caucellcloud-lab-operator` profile (or whatever
  `AWS_PROFILE` you configure)

## Setup

1. Install the AWS CLI if you don't already have it:

   ```bash
   brew install awscli   # macOS
   ```

2. Configure the `caucellcloud-lab-operator` profile with the `lab-operator` IAM user's
   static access key (get these from `terraform output -raw lab_operator_access_key_id`
   / `-raw lab_operator_secret_access_key`):

   ```bash
   aws configure --profile caucellcloud-lab-operator
   ```

   This prompts for the access key ID, secret access key, and default region, and writes
   them into `~/.aws/credentials` and `~/.aws/config`. Alternatively, edit those files
   directly:

   ```ini
   # ~/.aws/credentials
   [caucellcloud-lab-operator]
   aws_access_key_id = AKIA...
   aws_secret_access_key = ...
   ```

   ```ini
   # ~/.aws/config
   [profile caucellcloud-lab-operator]
   region = us-east-1
   ```

   `LabAPI` reads this profile via `AWS_PROFILE` (see below), so the name must match
   exactly. The `delete` command's MFA-gated `S3PhiBypassRole` assumption also relies on
   this profile's underlying IAM user having an MFA device registered.

3. Install Julia dependencies:

   ```bash
   julia --project=. -e 'using Pkg; Pkg.instantiate()'
   ```

4. Copy `.env.example` to `.env` and fill in the values (`LAB_OPERATOR_ROLE_ARN` is
   required; everything else has a default):

   ```bash
   cp .env.example .env
   ```

   `.env` is loaded automatically on first use and only fills in variables not already
   set in your environment.

## Build (optional but recommended)

The CLIs work without a build step, but every invocation pays Julia's JIT/precompile cost
(AWS.jl in particular is slow to load cold). Build a sysimage once to make invocations
start instantly:

```bash
julia --project=. build_sysimage.jl
```

This produces `lab.so` in the project root. It takes a few minutes. Rebuild it whenever
you change code under `src/LabAPI/`, `LabCustomersAPI.jl`, or `LabVendorAPI.jl`, or update
dependencies.

## Running

### Via the shortened commands

`labcustomers` and `labvendors` are the launcher scripts at the project root. They
resolve their own location, so they work whether run directly or via a symlink on your
`PATH`, and automatically pick up `lab.so` if it's been built (falling back to a plain
`julia` invocation — with a warning — if not).

From inside `LabCloud.jl/`:

```bash
./labcustomers list
./labvendors list
```

To use them as bare commands (`labcustomers ...` / `labvendors ...`) from anywhere,
put `LabCloud.jl/` on your `PATH`, e.g. in `~/.zshrc`:

```bash
export PATH="$PATH:/path/to/LabCloud.jl"
```

or symlink them onto a directory already on your `PATH`:

```bash
ln -s /path/to/LabCloud.jl/labcustomers /usr/local/bin/labcustomers
ln -s /path/to/LabCloud.jl/labvendors /usr/local/bin/labvendors
```

Then run them from anywhere:

```bash
labcustomers list
labvendors create genewiz
```

### Directly with Julia

Equivalent to what the launcher scripts do:

```bash
julia --project=. --sysimage lab.so LabCustomersAPI.jl <command>
julia --project=. --sysimage lab.so LabVendorAPI.jl <command>
```

Drop `--sysimage lab.so` if you haven't built it.

## Commands

### `labcustomers`

| Command | Description |
|---|---|
| `list` | List all lab customers |
| `create <name>` | Provision a bucket + IAM user for a new customer (TitleCase name, e.g. `JohnSmith`) |
| `get <name>` | Show details for a customer |
| `rotate <name>` | Rotate a customer's credentials |
| `migrate-policy-settings <name>` | Re-apply bucket hardening and IAM policy to an existing customer |
| `delete <name> --mfa=<code> [--yes]` | Delete a customer, their IAM user, and bucket (requires MFA) |
| `status [--researcher=<name>] [--nas-path=<path>]` | Read-only reconcile of NAS vs DB vs AWS |
| `push [--researcher=<name>] [--nas-path=<path>] [--dry-run]` | Discover researchers on NAS, provision missing ones, and sync populated prefixes to S3 |

### `labvendors`

| Command | Description |
|---|---|
| `list` | List all lab vendors |
| `create <name>` | Provision a landing bucket + IAM user for a new vendor (lowercase slug, e.g. `genewiz`) |
| `get <name>` | Show details for a vendor |
| `rotate <name>` | Rotate a vendor's credentials |
| `new-order <vendor> [--notes=<text>]` | Mint a new `{uuid}/` order prefix under the vendor's landing bucket |
| `list-orders <vendor>` | List all orders for a vendor |
| `delete <name> --mfa=<code> [--yes]` | Delete a vendor, their IAM user, bucket, and orders (requires MFA) |

Run any command with `--help` for its full option list (Comonicon generates this
automatically), e.g. `labcustomers create --help`.

## Testing

```bash
julia --project=. --sysimage lab.so test/runtests.jl
```

Offline unit tests always run. LocalStack-backed provisioning/S3/upload tests only run
when `AWS_ENDPOINT_URL` is set.
