#!/usr/bin/env bash
# Prints the next release version (without a leading "v").
#
#   next-version.sh BASE_VERSION BUMP
#
# BASE_VERSION is the latest released version, e.g. 0.2.0 (tag v0.2.0).
# BUMP is one of: auto, patch, minor, major.
#
# `auto` reads the Conventional Commits since the tag v<BASE_VERSION> (the
# whole history if that tag does not exist):
#
#   breaking (`type!:` or a `BREAKING CHANGE` footer)  -> major, or minor while
#                                                         the major version is 0
#   feat                                               -> minor
#   anything else                                      -> patch
#
# It fails when there are no commits to release. The decision lives here rather
# than in git-cliff's own bump logic, whose handling of 0.x differs between
# versions; git-cliff only writes the changelog.
set -euo pipefail

base="${1:?usage: next-version.sh BASE_VERSION BUMP}"
bump="${2:?usage: next-version.sh BASE_VERSION BUMP}"

if ! [[ "$base" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "next-version: '$base' is not MAJOR.MINOR.PATCH" >&2
  exit 2
fi
major=${BASH_REMATCH[1]} minor=${BASH_REMATCH[2]} patch=${BASH_REMATCH[3]}

level="$bump"
if [ "$bump" = auto ]; then
  if git rev-parse -q --verify "refs/tags/v$base" >/dev/null; then
    range="v$base..HEAD"
  else
    range="HEAD"
  fi

  subjects=$(git log --format=%s "$range" | grep -v '^chore(release)' || true)
  if [ -z "$subjects" ]; then
    echo "next-version: no commits since v$base, nothing to release" >&2
    exit 1
  fi

  bodies=$(git log --format=%b "$range" | grep -v '^$' || true)
  if grep -qE '^[a-zA-Z]+(\([^)]*\))?!:' <<<"$subjects" ||
    grep -qE '^BREAKING[ -]CHANGE' <<<"$bodies"; then
    if [ "$major" -ge 1 ]; then level=major; else level=minor; fi
    reason="a breaking change"
  elif grep -qE '^feat(\([^)]*\))?:' <<<"$subjects"; then
    level="minor"
    reason="a new feature"
  else
    level="patch"
    reason="no feature or breaking change"
  fi
  echo "next-version: auto -> $level ($reason since v$base)" >&2
fi

case "$level" in
  major) echo "$((major + 1)).0.0" ;;
  minor) echo "$major.$((minor + 1)).0" ;;
  patch) echo "$major.$minor.$((patch + 1))" ;;
  *)
    echo "next-version: unknown bump '$bump' (auto, patch, minor, major)" >&2
    exit 2
    ;;
esac
