package builtin

// Allow returns the list of built-in allowed command patterns.
// These are prefix-matched against extracted command tokens.
func Allow() []string {
	return concat(
		// Manually curated common safe commands
		fileViewers(),
		fileNav(),
		searchTools(),
		textProcessing(),
		systemInfo(),
		networkReadOnly(),
		gitSafeRead(), gitSafeWrite(),
		ghReadOnly(),
		goCommands(),
		cargoCommands(),
		nodeCommands(),
		pythonCommands(),
		containerCommands(),
		makeCommands(),
		builtinShell(),
		utilityCommands(),
		editorCommands(),
		buildCommands(),
		mediaCommands(),
		archiveCommands(),
		processCommands(),
		permissionCommands(),
		ossCommands(),
		// Auto-converted from safe-chains TOML definitions (450+ tools)
		generatedAllow(),
	)
}

// Deny returns built-in denied command patterns.
func Deny() []string {
	return concat(
		fileDestruction(),
		privilegeEscalation(),
		systemModification(),
		dangerousNetwork(),
		databaseDangerous(),
		cryptoKeys(),
		packageDestructive(),
		dockerDestructive(),
		shellDangerous(),
	)
}

// Ask returns built-in ask patterns.
func Ask() []string {
	return concat(
		gitAsk(),
		ghAsk(),
		deploymentCommands(),
		installCommands(),
	)
}

// DenyFlags returns built-in flag-level deny rules.
func DenyFlags() map[string][]string {
	return map[string][]string{
		"find":  {"-exec", "-execdir", "-delete", "-ok", "-okdir", "-fls", "-fprint", "-fprintf", "-print", "-printf"},
		"sed":   {"-i", "--in-place"},
		"tar":   {"--to-command", "-I", "--use-compress-program", "--checkpoint-action"},
		"curl":  {"--output", "-o", "--remote-name", "-O", "--upload-file", "-T"},
		"wget":  {"-O", "--output-document", "-o", "--output-file"},
		"dd":    {"if=", "of="},
		"git":    {},
		"docker": {"exec", "-it", "--interactive", "--tty"},
		"kill":  {"-9", "--signal"},
		"python": {"-c"},
		"chmod":  {"-R", "--recursive"},
		"chown": {"-R", "--recursive"},
	}
}

// ─── Category helpers ──────────────────────────────────────────

func concat(lists ...[]string) []string {
	var n int
	for _, l := range lists {
		n += len(l)
	}
	r := make([]string, 0, n)
	for _, l := range lists {
		r = append(r, l...)
	}
	return r
}

// ─── File viewers ─────────────────────────────────────────────

func fileViewers() []string {
	return []string{
		"cat", "bat", "delta",
		"head", "tail",
		"less", "more", "most",
		"tac", "rev",
		"nl", "number",
		"od", "xxd", "hexdump", "hexyl",
		"strings",
		"base64",
	}
}

// ─── File / directory navigation ──────────────────────────────

func fileNav() []string {
	return []string{
		"ls", "eza", "exa", "tree", "locate",
		"file", "stat",
		"du", "dust", "ncdu",
		"df", "duf",
		"which", "whereis", "type",
		"cd", "pwd",
		"readlink", "realpath",
		"fd", "fdfind",
		"walk",
		"mkdir", "touch",
		}
	}

// ─── Search & filtering ───────────────────────────────────────

func searchTools() []string {
	return []string{
		"grep", "rg", "ripgrep", "ag", "ack", "fgrep", "egrep",
		"jq", "yq",
		"fzf",
		"tokei",
		"cloc",
		"gron",
		"xargs",
		"find",
	}
}

// ─── Text processing ──────────────────────────────────────────

func textProcessing() []string {
	return []string{
		"cut", "sort", "uniq", "wc",
		"tr", "column",
		"diff", "cmp", "comm",
		"echo", "printf", "yes", "seq",
		"basename", "dirname",
		"fold", "fmt", "pr",
		"expand", "unexpand",
		"paste", "join",
		"tsort",
		"iconv", "uconv",
		"sponge",
		"pee",
	}
}

// ─── System info & monitoring ─────────────────────────────────

func systemInfo() []string {
	return []string{
		"date", "cal", "calender",
		"uptime", "w", "who", "users",
		"whoami", "hostname", "hostnamectl",
		"uname", "arch", "nproc",
		"env", "printenv",
		"ps", "top", "htop", "btop", "procs",
		"vm_stat", "vmstat",
		"iostat", "mpstat",
		"time", "uptime",
		"lscpu", "lsblk", "lspci", "lsusb", "lsmem",
		"lshw",
		"sysctl", "sysinfo",
		"nvidia-smi",
		"neofetch", "fastfetch", "screenfetch",
		"dmesg",
		"id", "groups", "logname",
		"locale", "localectl",
		"timedatectl",
		"sw_vers",
		"defaults read", "defaults export",
		"plutil",
		"osascript -e",
	}
}

// ─── Network (read-only) ──────────────────────────────────────

func networkReadOnly() []string {
	return []string{
		"ping", "ping6",
		"dig", "nslookup", "host",
		"whois",
		"curl",
		"wget",
		"xh", "httpie", "http",
		"netstat", "ss",
		"ifconfig", "ip",
		"traceroute", "traceroute6", "mtr",
		"arp", "arping",
		"hostname",
		"dns-sd",
		"iwconfig", "iw",
		"iwlist",
		"iwgetid",
		"nmcli",
		"nmap",
		"tcpdump",
		"nc", "netcat",
		"doggo",
		"hurl",
		"grpcurl",
		"protoc",
	}
}

// ─── Git (read-only) ──────────────────────────────────────────

func gitSafeRead() []string {
	return []string{
		"git status", "git log", "git diff", "git show",
		"git branch", "git tag", "git remote",
		"git blame", "git shortlog", "git describe",
		"git rev-parse", "git merge-base",
		"git config",
		"git config --get", "git config --list",
		"git config --global --get", "git config --global --list",
		"git config --local --get", "git config --local --list",
		"git ls-files", "git ls-tree", "git cat-file",
		"git stash list", "git stash show",
		"git diff-tree", "git diff-index", "git diff-files",
		"git for-each-ref",
		"git help",
		"git version",
		"git whatchanged",
		"git name-rev",
		"git count-objects",
		"git check-ignore",
		"git check-attr",
		"git check-mailmap",
		"git verify-pack",
		"git verify-tag",
		"git verify-commit",
		"git cherry",
		"git cherry-pick --no-commit",
		"git notes list", "git notes show",
		"git reflog",
		"git submodule status",
		"git worktree list",
		"git bisect visualize",
		"git grep",
		"git range-diff",
		"git interpret-trailers --parse",
	}
}

func gitSafeWrite() []string {
	return []string{
		"git fetch",
		"git pull",
		"git add",
		"git commit",
		"git commit --allow-empty",
		"git checkout",
		"git switch",
		"git switch -c",
		"git checkout -b",
		"git init",
		"git clone",
		"git stash",
		"git stash push",
		"git stash apply",
		"git stash pop",
		"git stash drop",
		"git clean",
		"git clean -d",
		"git rm",
		"git mv",
		"git notes add",
		"git notes append",
		"git worktree add",
		"git cherry-pick",
		"git revert",
		"git rebase --continue",
		"git rebase --abort",
		"git merge --abort",
	}
}

// ─── Git (ask) ────────────────────────────────────────────────

func gitAsk() []string {
	return []string{
		"git push",
		"git merge",
		"git rebase",
		"git rebase -i",
		"git reset",
		"git reset --hard",
		"git branch -d", "git branch -D",
		"git tag -d", "git tag --delete",
		"git tag -a",
		"git push --force", "git push -f",
		"git gc",
		"git prune",
		"git submodule update",
		"git bisect reset",
		"git am",
		"git apply",
		"git format-patch",
		"git send-email",
		"git archive",
		"git bundle",
	}
}

// ─── GitHub CLI ───────────────────────────────────────────────

func ghReadOnly() []string {
	return []string{
		"gh repo view", "gh repo list",
		"gh issue list", "gh issue view",
		"gh pr list", "gh pr view", "gh pr status", "gh pr checks", "gh pr diff",
		"gh release list", "gh release view",
		"gh run list", "gh run view", "gh run download",
		"gh workflow list", "gh workflow view", "gh workflow run",
		"gh auth status",
		"gh gist list", "gh gist view",
		"gh search",
		"gh secret list",
		"gh variable list",
		"gh cache list",
		"gh api",
		"gh copilot",
		"gh label list",
		"gh project list",
		"gh rule list",
		"gh ssh-key list",
	}
}

func ghAsk() []string {
	return []string{
		"gh issue create", "gh issue close", "gh issue reopen",
		"gh pr create", "gh pr merge", "gh pr close", "gh pr reopen",
		"gh release create",
		"gh gist create",
		"gh secret set",
		"gh variable set",
	}
}

// ─── Go ───────────────────────────────────────────────────────

func goCommands() []string {
	return []string{
		"go version", "go env", "go doc", "go help",
		"go list",
		"go vet", "go vet -vettool",
		"go build",
		"go build -o",
		"go install",
		"go test",
		"go test -run", "go test -bench", "go test -count", "go test -v",
		"go mod tidy", "go mod download", "go mod init",
		"go mod graph", "go mod verify", "go mod why",
		"go mod vendor", "go mod edit",
		"go generate",
		"go fmt", "gofmt", "go fix",
		"go get",
		"go clean",
		"go run",
		"go vet",
		"go tool",
		"go work init", "go work use", "go work edit", "go work sync",
		"go vet",
	}
}

// ─── Rust / Cargo ─────────────────────────────────────────────

func cargoCommands() []string {
	return []string{
		"cargo version", "cargo help",
		"cargo check", "cargo c",
		"cargo build",
		"cargo build --release",
		"cargo test",
		"cargo bench",
		"cargo doc",
		"cargo doc --open",
		"cargo clippy",
		"cargo fix",
		"cargo fmt",
		"cargo fmt --check",
		"cargo update",
		"cargo metadata",
		"cargo tree",
		"cargo outdated",
		"cargo audit",
		"cargo deny",
		"cargo package",
		"cargo publish",
		"cargo init", "cargo new",
		"cargo clean",
		"cargo run",
		"cargo add",
		"cargo rm",
		"cargo upgrade",
		"cargo config",
		"cargo info",
		"cargo search",
		"cargo locate-project",
		"cargo pkgid",
		"cargo report",
		"cargo vendor",
		"cargo generate-lockfile",
		"cargo login",
		"cargo logout",
		"cargo owner",
		"cargo yank",
		"rustup show", "rustup default", "rustup toolchain list",
		"rustup target list", "rustup component list",
		"rustc --version", "rustc --help",
		"rustfmt",
	}
}

// ─── Node.js / JS ecosystem ───────────────────────────────────

func nodeCommands() []string {
	return []string{
		"node", "node -e", "node --version", "node --help",
		"npx",
		"npx --yes",
		"ts-node", "tsx", "tsc",
		"node --check",
		// npm
		"npm ls", "npm list", "npm outdated",
		"npm view", "npm info", "npm why",
		"npm audit",
		"npm config list", "npm config get",
		"npm pack",
		"npm install", "npm ci", "npm i",
		"npm uninstall",
		"npm run",
		"npm test", "npm start",
		"npm build",
		"npm dedupe",
		"npm prune",
		"npm fund",
		"npm doctor",
		"npm init",
		"npm help",
		"npm prefix", "npm root", "npm bin",
		"npm explore",
		"npm repo", "npm docs", "npm bugs",
		// yarn
		"yarn list", "yarn outdated", "yarn why",
		"yarn info",
		"yarn config",
		"yarn install",
		"yarn add",
		"yarn remove",
		"yarn run",
		"yarn test",
		"yarn workspace", "yarn workspaces",
		// pnpm
		"pnpm ls", "pnpm list", "pnpm outdated",
		"pnpm why",
		"pnpm config",
		"pnpm install",
		"pnpm add",
		"pnpm remove",
		"pnpm run",
		"pnpm test",
		// bun
		"bun install", "bun add", "bun remove",
		"bun run",
		"bun test",
		"bun pm ls", "bun pm hash",
		"bunx",
		// common tools
		"nvm", "nvm ls", "nvm ls-remote",
		"fnm", "fnm ls",
		"volta", "volta ls",
		"ncu",
		"prettier", "prettier --check",
		"eslint",
		"oxlint",
		"biome", "biome check",
		"stylelint",
		"markdownlint", "markdownlint-cli2",
		"tsc --noEmit",
		"vitest",
		"jest",
		"mocha",
		"ava",
		"playwright",
		"cypress",
		"vite", "vite build", "vite dev",
		"webpack", "webpack build",
		"rollup",
		"esbuild",
		"tsup",
		"parcel",
		"turbo", "turbo build", "turbo run",
		"nx", "nx build", "nx run",
		"nx test", "nx lint",
	}
}

// ─── Python ───────────────────────────────────────────────────

func pythonCommands() []string {
	return []string{
		"python", "python3",
		"python -c", "python3 -c",
		"python --version", "python3 --version",
		// pip
		"pip list", "pip show", "pip freeze",
		"pip check", "pip debug",
		"pip config list", "pip config get",
		"pip index",
		"pip install --dry-run",
		"pip download",
		"pip uninstall",
		"pip3 list", "pip3 show", "pip3 freeze",
		"pip3 check",
		"pip3 install",
		"pipx",
		// uv
		"uv", "uvx",
		"uv python",
		"uv pip list", "uv pip show", "uv pip freeze",
		"uv pip install",
		"uv venv",
		"uv build",
		"uv publish",
		"uv tool",
		// lint/format
		"ruff", "ruff check", "ruff format",
		"black", "black --check",
		"ruff --check",
		"autopep8",
		"isort", "isort --check",
		"pycodestyle",
		"pydocstyle",
		"pylint",
		"pyright",
		"mypy",
		"bandit",
		"semgrep",
		"deptry",
		"vulture",
		// test
		"pytest", "pytest -x", "pytest --cov",
		"tox", "nox",
		"coverage run", "coverage report", "coverage html",
		// build/publish
		"python setup.py",
		"python -m build",
		"twine check", "twine upload",
		// jupyter
		"jupyter", "jupyter notebook",
		"jupyter lab",
		"jupyter kernelspec list",
		"ipython",
		// tools
		"cookiecutter",
		"dbt",
		"pre-commit", "pre-commit run", "pre-commit install",
		"pip-compile",
		"pip-sync",
		"safety",
		"pip-audit",
		"conda list", "conda info", "conda search",
		"conda install",
		"mamba",
		"poetry", "poetry install", "poetry add",
		"poetry show",
		"mkdocs", "mkdocs serve", "mkdocs build",
		"sphinx-build", "sphinx-apidoc", "sphinx-quickstart",
		// ML
		"mlflow",
		"wandb",
		"scalene",
		"py-spy",
	}
}

// ─── Containers / Docker ──────────────────────────────────────

func containerCommands() []string {
	return []string{
		// Docker
		"docker ps", "docker images", "docker image ls",
		"docker logs", "docker inspect",
		"docker stats", "docker top",
		"docker diff", "docker history",
		"docker version", "docker info",
		"docker pull",
		"docker build", "docker buildx build",
		"docker compose", "docker-compose",
		"docker compose up", "docker compose down",
		"docker compose logs", "docker compose ps",
		"docker container ls",
		"docker network ls", "docker network inspect",
		"docker volume ls", "docker volume inspect",
		"docker system df",
		"docker search",
		"docker port",
		"docker export",
		"docker save",
		// Podman
		"podman ps", "podman images",
		"podman logs", "podman inspect",
		"podman pull",
		"podman build",
		// Kubernetes
		"kubectl get", "kubectl describe",
		"kubectl logs", "kubectl top",
		"kubectl explain",
		"kubectl api-resources", "kubectl api-versions",
		"kubectl cluster-info",
		"kubectl version",
		"kubectl config view", "kubectl config get-contexts",
		"kubectl config get-clusters",
		"kubectl diff",
		"kubectl wait",
		"kubectl label",
		"kubectl annotate",
		"kubectl apply",
		"kubectl delete",
		"kubectl exec",
		"kubectl run",
		"kubectl port-forward",
		"kubectl cp",
		"kubectl auth can-i",
		// Helm
		"helm list", "helm ls",
		"helm search", "helm repo list",
		"helm status", "helm history",
		"helm get", "helm show",
		"helm lint",
		"helm template",
		"helm install --dry-run",
		"helm upgrade --dry-run",
		"helm dependency list",
		"helm env",
		"helm version",
		// misc
		"kind", "kind get clusters",
		"minikube status", "minikube ip",
		"k3d",
		"crane", "crane ls", "crane catalog",
		"skopeo", "skopeo list-tags", "skopeo inspect",
		"dive",
		"trivy", "trivy image", "trivy fs",
		"grype",
		"syft",
		"cosign",
		"hadolint",
	}
}

// ─── Make ─────────────────────────────────────────────────────

func makeCommands() []string {
	return []string{
		"make", "make -j", "make --jobs",
		"cmake",
		"ninja",
		"meson",
		"bazel",
		"just",
	}
}

// ─── Shell builtins & wrappers ────────────────────────────────

func builtinShell() []string {
	return []string{
		"export", "unset",
		"test", "[", "]",
		"true", "false",
		"source", ".",
		"type", "command", "builtin",
		"alias", "unalias",
		"declare", "local", "readonly", "typeset",
		"read", "mapfile", "readarray",
		"shift",
		"return", "exit",
		"trap",
		"umask",
		"exec",
		"wait",
		"jobs", "fg", "bg",
		"disown",
		"ulimit",
		"hash",
	}
}

// ─── Utility commands ─────────────────────────────────────────

func utilityCommands() []string {
	return []string{
		// Wrappers
		"timeout", "time", "nice",
		"nohup", "stdbuf",
		"chronic", "ifne",
		"parallel",
		"entr",
		"watch",
		"pv",
		// Dev
		"open", "xdg-open",
		"mdfind", "mdls",
		"defaults",
		"plutil",
		"pbcopy", "pbpaste",
		"terminal-notifier",
		// Misc
		"cp", "mv", "ln", "install",
		"tee", "pee",
		"yes",
		"shuf",
		"envsubst",
		"gettext",
		"eval",
	}
}

// ─── Editor / Diff / Review ───────────────────────────────────

func editorCommands() []string {
	return []string{
		"sed", "awk",
		"gawk", "mawk",
		"nano", "vim", "nvim", "vi", "emacs", "code",
		"diff", "colordiff", "difft",
		"delta",
		"icdiff",
		"meld",
		"rg",
		"grep",
		"tig",
	}
}

// ─── Build tools (non-language-specific) ──────────────────────

func buildCommands() []string {
	return []string{
		"gcc", "g++", "clang", "clang++",
		"ld", "ar", "nm", "objdump", "readelf", "strings", "strip",
		"pkg-config",
		"ldd",
		"as",
		"valgrind",
		"strace", "dtruss",
		"ltrace",
		"gdb", "lldb",
		"perf",
		"asan",
	}
}

// ─── Media ────────────────────────────────────────────────────

func mediaCommands() []string {
	return []string{
		"ffprobe",
		"ffmpeg",
		"magick", "convert", "identify",
		"exiftool",
		"sox",
	}
}

// ─── Archive ──────────────────────────────────────────────────

func archiveCommands() []string {
	return []string{
		"tar",
		"gzip", "gunzip", "zcat",
		"bzip2", "bunzip2", "bzcat",
		"xz", "unxz", "xzcat",
		"zstd", "unzstd",
		"zip", "unzip",
		"7z", "7za", "7zr",
		"rar", "unrar",
		"lz4", "unlz4",
		"lzma", "unlzma",
		"compress", "uncompress",
		"cpio",
		"ar",
		"zpaq",
	}
}

// ─── Process ──────────────────────────────────────────────────

func processCommands() []string {
	return []string{
		"kill",
		"pkill", "pgrep",
		"killall",
		"renice",
		"nohup",
		"sleep",
	}
}

// ─── Permissions ──────────────────────────────────────────────

func permissionCommands() []string {
	return []string{
		"chmod",
		"chown",
		"chgrp",
		"umask",
	}
}

// ─── Open Source / Forges (read-only) ─────────────────────────

func ossCommands() []string {
	return []string{
		"glab",
	}
}

// ─── File destruction ─────────────────────────────────────────

func fileDestruction() []string {
	return []string{
		"rm",
		"rmdir",
		"trash",
		"shred",
		"wipe",
	}
}

// ─── Privilege escalation ─────────────────────────────────────

func privilegeEscalation() []string {
	return []string{
		"sudo",
		"doas",
		"su",
		"dzdo",
		"pfexec",
		"chroot",
	}
}

// ─── System modification ──────────────────────────────────────

func systemModification() []string {
	return []string{
		"reboot", "shutdown", "halt", "poweroff", "init",
		"systemctl",
		"service",
		"mkfs", "mkfs.ext4", "mkfs.btrfs", "mkfs.xfs",
		"fdisk", "gdisk", "cfdisk", "sfdisk", "parted",
		"mount", "umount",
		"dd",
		"fsck",
		"swapoff", "swapon",
		"lvm",
		"pvcreate", "vgcreate", "lvcreate",
		"cryptsetup",
		"grub-install", "grub-mkconfig",
		"update-grub",
		"apt-get install", "apt install", "apt-get remove", "apt remove",
		"apt-get purge", "apt purge",
		"apt-get autoremove", "apt autoremove",
		"dpkg -i", "dpkg --install",
		"dpkg --purge", "dpkg --remove",
		"rpm -i", "rpm --install",
		"rpm -e", "rpm --erase",
		"snap install", "snap remove",
		"flatpak install",
		"brew install", "brew uninstall",
		"brew upgrade", "brew update",
		"port install",
		"pacman -S", "pacman -R", "pacman -U",
		"yum install", "yum remove",
		"dnf install", "dnf remove",
		"zypper install", "zypper remove",
		"nix-env -i", "nix-env -e",
		"crontab",
		"fc-cache",
	}
}

// ─── Dangerous network ops ────────────────────────────────────

func dangerousNetwork() []string {
	return []string{
		"sshd",
		"ssh-agent",
	}
}

// ─── Database dangerous ───────────────────────────────────────

func databaseDangerous() []string {
	return []string{
		"drop table",
		"drop database",
		"truncate table",
	}
}

// ─── Crypto / Keys ────────────────────────────────────────────

func cryptoKeys() []string {
	return []string{
		"ssh-keygen",
		"gpg",
		"gpg2",
		"openssl",
	}
}

// ─── Package management destructive ───────────────────────────

func packageDestructive() []string {
	return []string{
		"apt-get remove", "apt-get purge", "apt-get autoremove",
		"apt remove", "apt purge", "apt autoremove",
		"dpkg --purge", "dpkg --remove",
		"rpm -e",
		"brew uninstall",
	}
}

// ─── Docker destructive ───────────────────────────────────────

func dockerDestructive() []string {
	return []string{
		"docker rmi",
		"docker rm",
		"docker system prune",
		"docker system df",
		"docker volume rm",
		"docker volume prune",
		"docker network rm",
		"docker network prune",
		"docker container prune",
		"docker image prune",
		"docker builder prune",
		"docker compose down -v",
		"docker compose rm",
	}
}

// ─── Shell dangerous ──────────────────────────────────────────

func shellDangerous() []string {
	return []string{
		"eval",
	}
}

// ─── Deployment / ask ─────────────────────────────────────────

func deploymentCommands() []string {
	return []string{
		"kubectl apply",
		"kubectl delete",
		"kubectl rollout",
		"kubectl scale",
		"helm install",
		"helm upgrade",
		"helm uninstall",
		"helm rollback",
		"terraform apply",
		"terraform destroy",
		"tofu apply",
		"tofu destroy",
		"pulumi up",
		"pulumi destroy",
		"serverless deploy",
		"sls deploy",
		"vercel deploy", "vercel --prod",
		"netlify deploy",
		"flyctl deploy",
		"railway up",
		"wrangler deploy",
		"wrangler publish",
		"aws ec2",
		"aws s3 cp", "aws s3 mv", "aws s3 rm", "aws s3 sync",
		"gcloud compute",
		"az vm",
		"doctl compute",
		"scw",
		"hcloud",
	}
}

// ─── Install commands / ask ───────────────────────────────────

func installCommands() []string {
	return []string{
		"cargo install",
		"go install",
		"npm install -g",
		"yarn global add",
		"pnpm add -g",
		"pip install",
		"pip3 install",
		"uv pip install",
		"brew install",
		"brew cask install",
	}
}
