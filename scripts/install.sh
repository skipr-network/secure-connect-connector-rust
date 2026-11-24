#!/bin/sh
#
# TT-1875: the one-line Connector installer. Downloads the prebuilt Connector for this host's CPU
# from a GitHub Release, checks it against the release's SHA256SUMS, unpacks it and hands over to
# the packaged install-systemd.sh - no Rust toolchain, C compiler or git needed on this host.
#
#   curl -fsSL <url of this script> | AGENTS_JSON_URL=... REGISTRY_BASE_URL=... sh
#
# Run it as the normal user the service should run as (like install-systemd.sh, it uses sudo for
# what needs root and refuses to install a service that runs as root).
#
# Environment:
#   AGENTS_JSON_URL, REGISTRY_BASE_URL, CONNECTOR_CA_BUNDLE_URL, CONNECTOR_USER
#                           passed on to install-systemd.sh (packaging/install-systemd.sh).
#                           Portal's Deploy Connector screen fills in the first two.
#   CONNECTOR_VERSION       the release tag to install, e.g. v0.2.0 or v0.2.1-dev.0123abcd9.
#                           Default: the latest release (never a pre-release).
#   CONNECTOR_RELEASES_URL  where releases are downloaded from. Default: this repository's GitHub
#                           releases. Set it to a mirror for hosts without access to GitHub.
#   CONNECTOR_INSTALL_DIR   where the package is unpacked and kept. Default: ~/secure-connect-connector.
#                           Run ./packaging/install-systemd.sh --uninstall or --decommission from there.
#
# Options after `sh -s --` go to install-systemd.sh, e.g. `... | sh -s -- --regenerate-identity`.
#
# POSIX sh, not bash: `curl ... | sh` runs this with whatever /bin/sh is (dash on Debian/Ubuntu).
# Everything is inside main(), called on the last line, so a download cut short runs nothing.

set -eu

DEFAULT_RELEASES_URL="https://github.com/skipr-network/secure-connect-connector-rust/releases"

say() {
  echo "$*"
}

fail() {
  echo "error: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "'$1' is required to install the Connector - install it and run this command again."
}

# The release package name for this host's CPU: x86_64 or aarch64, the two the release builds.
detect_arch() {
  machine="$(uname -m)"
  case "$machine" in
    x86_64 | amd64) echo x86_64 ;;
    aarch64 | arm64) echo aarch64 ;;
    *) fail "no prebuilt Connector for this CPU ($machine) - only x86_64 and aarch64 are released. Build it from source instead." ;;
  esac
}

# The tag of the latest release: GitHub's .../releases/latest redirects to .../releases/tag/<tag>,
# with no API call (so no API rate limit). Pre-releases are never "latest".
latest_version() {
  effective_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "$RELEASES_URL/latest" 2>/dev/null)" ||
    fail "could not find the latest Connector release at $RELEASES_URL/latest - there may be no release yet. Set CONNECTOR_VERSION to a release tag."
  tag="${effective_url##*/}"
  case "$tag" in
    v[0-9]*) echo "$tag" ;;
    *) fail "could not find the latest Connector release at $RELEASES_URL/latest - there may be no release yet. Set CONNECTOR_VERSION to a release tag." ;;
  esac
}

download() {
  curl -fsSL --retry 3 -o "$2" "$1" || fail "could not download $1"
}

main() {
  [ "$(uname -s)" = Linux ] || fail "the Connector runs on Linux only."
  need curl
  need tar
  need sha256sum
  need sudo

  RELEASES_URL="${CONNECTOR_RELEASES_URL:-$DEFAULT_RELEASES_URL}"
  RELEASES_URL="${RELEASES_URL%/}"
  INSTALL_DIR="${CONNECTOR_INSTALL_DIR:-$HOME/secure-connect-connector}"

  arch="$(detect_arch)"
  version="${CONNECTOR_VERSION:-}"
  if [ -z "$version" ]; then
    version="$(latest_version)"
  fi
  case "$version" in
    v*) ;;
    *) version="v$version" ;;
  esac
  package="secure_connect_connector-${version#v}-${arch}-linux"

  say "Installing Connector $version ($arch) from $RELEASES_URL"

  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT INT TERM
  download "$RELEASES_URL/download/$version/$package.tar.gz" "$work/$package.tar.gz"
  download "$RELEASES_URL/download/$version/SHA256SUMS" "$work/SHA256SUMS"

  # Only the line for this package, and it must be there: a SHA256SUMS that does not list the
  # package proves nothing about it.
  grep "  $package.tar.gz\$" "$work/SHA256SUMS" > "$work/package.sha256" ||
    fail "$package.tar.gz is not listed in the release's SHA256SUMS - not installing it."
  (cd "$work" && sha256sum -c package.sha256 >/dev/null 2>&1) ||
    fail "$package.tar.gz does not match the release's SHA256SUMS - the download is incomplete or was changed. Not installing it."
  say "Checksum OK ($package.tar.gz)"

  tar -xzf "$work/$package.tar.gz" -C "$work"
  if [ ! -x "$work/$package/packaging/install-systemd.sh" ] || [ ! -x "$work/$package/target/release/secure_connect_connector" ]; then
    fail "$package.tar.gz does not contain the expected files - not installing it."
  fi

  # Kept, not deleted after the install: --uninstall and --decommission are run from here later.
  # Replaced as a whole, so nothing of an older version is left next to the new one - but only an
  # empty folder or an earlier install: a CONNECTOR_INSTALL_DIR pointing anywhere else is refused,
  # never deleted.
  if [ -e "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ] && [ ! -f "$INSTALL_DIR/packaging/install-systemd.sh" ]; then
    fail "$INSTALL_DIR already exists and is not an earlier Connector install - not replacing it. Set CONNECTOR_INSTALL_DIR to another folder."
  fi
  rm -rf "$INSTALL_DIR"
  mkdir -p "$(dirname "$INSTALL_DIR")"
  mv "$work/$package" "$INSTALL_DIR"
  say "Unpacked to $INSTALL_DIR"

  # The command: `env NAME=value ... install-systemd.sh <options>`. Only the settings that are set
  # are passed - one left out keeps what this host's connector.env already has, so an upgrade needs
  # nothing but this command again. Through `env`, not `sudo NAME=value`, which some sudo policies
  # refuse.
  set -- "$INSTALL_DIR/packaging/install-systemd.sh" "$@"
  for name in CONNECTOR_USER CONNECTOR_CA_BUNDLE_URL REGISTRY_BASE_URL AGENTS_JSON_URL; do
    eval "value=\${$name:-}"
    if [ -n "$value" ]; then
      set -- "$name=$value" "$@"
    fi
  done

  # `curl ... | sh` makes this script's stdin the download itself: install-systemd.sh must not read
  # it. Its questions go to the terminal when there is one, and get their defaults when there is not.
  if [ -t 1 ] && (exec </dev/tty) 2>/dev/null; then
    # shellcheck disable=SC2024 # the admin's own terminal, opened as the admin - meant that way
    sudo env "$@" </dev/tty
  else
    sudo env "$@" </dev/null
  fi
}

main "$@"
