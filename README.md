# jkbase

A self-hostable platform for deploying static sites, WASM functions, and server containers — each project runs in its own Firecracker microVM.

## Install the CLI

```bash
cargo install --path crates/jkbase-cli
```

## Quick start

### 1. Create an account

```bash
jkbase init you@example.com
```

This creates your account and saves an API token to `~/.jkbase/credentials`.

If you already have a token, use `jkbase login --token YOUR_TOKEN` instead.

### 2. Create a project

```bash
jkbase project create my-app
```

### 3. Add a `jkbase.toml`

Create a `jkbase.toml` in your project directory:

```toml
[project]
name = "my-app"

[hosting]
public = "./dist"
spa = true
```

`public` is the directory containing your built static files (e.g. `./dist`, `./build`, `./public`). Set `spa = true` if your app uses client-side routing.

### 4. Deploy

```bash
jkbase deploy
```

Your site is live at `https://my-app.jkbase.app`.

## Project configuration

All configuration lives in `jkbase.toml`. Here's a full example:

```toml
[project]
name = "my-app"

# Static site hosting
[hosting]
public = "./dist"
spa = true

# Server container
[servers.api]
dockerfile = "./Dockerfile"
port = 8080
health_check = { path = "/health", interval = "10s", timeout = "5s" }
volumes = [{ name = "data", mount = "/app/data" }]

# Route requests to the server
[routes]
"/api/*" = { service = "server", name = "api" }
```

### Static sites

The simplest setup — point `hosting.public` at your build output:

```toml
[hosting]
public = "./dist"
spa = true
```

### Multi-site hosting

Serve multiple static directories with prefix routing:

```toml
[sites.docs]
public = "./docs/build"
prefix = "/docs"

[sites.blog]
public = "./blog/out"
prefix = "/blog"
```

### Server containers

Run a Docker container alongside your static site. The container runs inside the project's microVM with its own port and optional persistent storage:

```toml
[servers.api]
dockerfile = "./Dockerfile"
port = 8080
health_check = { path = "/health", interval = "10s", timeout = "5s" }
volumes = [{ name = "data", mount = "/app/data" }]
```

Volumes persist across deploys.

### Routing

Route URL paths to your server containers:

```toml
[routes]
"/api/*" = { service = "server", name = "api" }
```

### Custom domains

```toml
domains = ["example.com", "www.example.com"]
```

## Managing secrets

```bash
jkbase secret set DATABASE_URL=postgres://...
jkbase secret list
jkbase secret rm DATABASE_URL
```

Secrets are scoped to the project in your `jkbase.toml` (or use `--project`).

## CLI reference

| Command | Description |
|---|---|
| `jkbase init <email>` | Create account and save token |
| `jkbase login` | Authenticate with an existing token |
| `jkbase project create <name>` | Create a new project |
| `jkbase project list` | List all projects |
| `jkbase project info [name]` | Show project details |
| `jkbase project delete <name>` | Delete a project |
| `jkbase deploy` | Deploy the current project |
| `jkbase secret set KEY=value` | Set a secret |
| `jkbase secret list` | List secrets |
| `jkbase secret rm KEY` | Remove a secret |

All commands accept `--api URL` to override the platform endpoint (defaults to `https://api.jkbase.app`). The auth token can also be set via the `JKBASE_TOKEN` environment variable.
