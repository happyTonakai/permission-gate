package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/happyTonakai/permission-gate/internal/update"
)

// runUpdate implements the `pgate update` subcommand. It is deliberately
// opt-in: no background checks, no auto-update at startup. The user typed
// `pgate update`, so we run a single GitHub API round-trip and (if needed)
// replace the running binary in place.
//
// Three guards before we touch the filesystem:
//  1. version == "dev" refuses (can't safely overwrite a `go run` build).
//  2. current == target prints "Already on …" and exits 0 — unless --force.
//  3. download is sanity-checked for an ELF/Mach-O magic number inside the
//     internal/update package, so a 404 returning HTML doesn't silently
//     corrupt the binary.
func runUpdate(args []string) {
	if version == "dev" {
		fmt.Fprintln(os.Stderr,
			"pgate was built from source (version=dev) and cannot self-update.")
		fmt.Fprintln(os.Stderr,
			"Reinstall via your package manager or run:")
		fmt.Fprintln(os.Stderr,
			"    go install github.com/happyTonakai/permission-gate/cmd/pgate@latest")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("update", flag.ExitOnError)
	toTag := fs.String("to", "", "Update to a specific version tag (e.g. v1.2.3)")
	force := fs.Bool("force", false, "Re-download even if already at the requested version")
	fs.Parse(args)

	target, err := resolveTarget(*toTag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	current := normalizeVer(version)
	targetNorm := normalizeVer(target)
	if current == targetNorm && !*force {
		fmt.Printf("Already on latest version v%s\n", current)
		return
	}

	direction := "Updating"
	switch {
	case current == targetNorm && *force:
		direction = "Re-installing"
	case compareSemverish(current, targetNorm) < 0:
		direction = "Upgrading"
	case compareSemverish(current, targetNorm) > 0:
		direction = "Downgrading"
	}
	fmt.Printf("%s: v%s -> v%s ...\n", direction, current, targetNorm)

	payload, err := update.Download(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine pgate binary path: %v\n", err)
		os.Exit(1)
	}
	if err := update.Replace(self, payload); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintln(os.Stderr,
			"Hint: if you installed pgate via 'go install', run that command again instead.")
		os.Exit(1)
	}

	fmt.Printf("Updated pgate to v%s\n", targetNorm)
	fmt.Println("Run 'pgate version' to verify.")
}

// resolveTarget returns the canonical tag (with "v" prefix) that we should
// update to, normalizing user input and surfacing GitHub 404s with a clear
// message.
func resolveTarget(toFlag string) (string, error) {
	if toFlag != "" {
		tag := normalizeVer(toFlag)
		canonical, err := update.FetchTag("v" + tag)
		if err != nil {
			return "", fmt.Errorf("lookup %s: %w", "v"+tag, err)
		}
		return canonical, nil
	}
	latest, err := update.FetchLatest()
	if err != nil {
		return "", fmt.Errorf("lookup latest: %w", err)
	}
	return latest, nil
}

// normalizeVer strips a leading "v"/"V" so version comparisons are
// case-insensitive: "v1.2.3", "V1.2.3", "1.2.3" all collapse to "1.2.3".
func normalizeVer(s string) string {
	if len(s) > 0 && (s[0] == 'v' || s[0] == 'V') {
		return s[1:]
	}
	return s
}

// compareSemverish does a quick numeric compare without going full semver:
// splits on '.', parses each component as int, falls back to string
// compare for non-numeric parts. It's only used to label the output
// ("Upgrading" vs "Downgrading"), so being approximate is fine. Pre-release
// suffixes (rc1, beta2) are treated as strings — `1.2.3-rc1` won't compare
// cleanly against `1.2.3` because "-" isn't a '.' delimiter, but that's
// an acceptable corner case for a label.
func compareSemverish(a, b string) int {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var sa, sb string
		if i < len(pa) {
			sa = pa[i]
		} else {
			sa = "0"
		}
		if i < len(pb) {
			sb = pb[i]
		} else {
			sb = "0"
		}
		if sa == sb {
			continue
		}
		// Numeric compare when both halves parse cleanly; otherwise fall
		// back to lexicographic, which is good enough for our "label only"
		// usage.
		if na, errA := strconv.Atoi(sa); errA == nil {
			if nb, errB := strconv.Atoi(sb); errB == nil {
				switch {
				case na < nb:
					return -1
				case na > nb:
					return 1
				}
				return 0
			}
		}
		return strings.Compare(sa, sb)
	}
	return 0
}
