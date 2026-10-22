#!/usr/bin/env bash
# Tests next-version.sh against throwaway git repositories.
set -uo pipefail

script="$(cd "$(dirname "$0")" && pwd)/next-version.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failed=0

# repo NAME TAG COMMIT...   (a commit message may contain a body after a blank line)
repo() {
  local dir="$work/$1" tag="$2"
  shift 2
  mkdir -p "$dir" && git -C "$dir" init -q
  git -C "$dir" config user.email t@t && git -C "$dir" config user.name t
  git -C "$dir" commit -q --allow-empty -m "chore: init"
  [ -n "$tag" ] && git -C "$dir" tag "$tag"
  local msg
  for msg in "$@"; do git -C "$dir" commit -q --allow-empty -m "$msg"; done
  echo "$dir"
}

# expect DESCRIPTION WANT DIR BASE BUMP     (WANT "FAIL" = non-zero exit)
expect() {
  local desc="$1" want="$2" dir="$3" got rc
  got=$(cd "$dir" && "$script" "$4" "$5" 2>/dev/null)
  rc=$?
  if [ "$want" = FAIL ]; then
    if [ "$rc" -ne 0 ]; then
      echo "  ok    $desc"
    else
      echo "  FAIL  $desc: expected failure, got '$got'"
      failed=1
    fi
  elif [ "$rc" -eq 0 ] && [ "$got" = "$want" ]; then
    echo "  ok    $desc -> $got"
  else
    echo "  FAIL  $desc: want $want, got '$got' (exit $rc)"
    failed=1
  fi
}

echo "auto, 0.x"
expect "docs only"            0.2.1 "$(repo a v0.2.0 'docs: tweak')"                          0.2.0 auto
expect "fix"                  0.2.1 "$(repo b v0.2.0 'fix: bug')"                             0.2.0 auto
expect "feat"                 0.3.0 "$(repo c v0.2.0 'fix: bug' 'feat: thing')"               0.2.0 auto
expect "scoped feat"          0.3.0 "$(repo d v0.2.0 'feat(core): thing')"                    0.2.0 auto
expect "feat!, stays in 0.x"  0.3.0 "$(repo e v0.2.0 'feat!: drop it')"                       0.2.0 auto
expect "fix!, stays in 0.x"   0.3.0 "$(repo f v0.2.0 'fix(api)!: change')"                    0.2.0 auto
expect "BREAKING CHANGE body" 0.3.0 "$(repo g v0.2.0 $'refactor: x\n\nBREAKING CHANGE: y')"   0.2.0 auto
expect "release commit only"  FAIL  "$(repo h v0.2.0 'chore(release): v0.2.0')"               0.2.0 auto
expect "no commits"           FAIL  "$(repo i v0.2.0)"                                        0.2.0 auto
expect "feat inside a word"   0.2.1 "$(repo j v0.2.0 'docs: feature list')"                   0.2.0 auto

echo "auto, 1.x"
expect "fix"                  1.2.4 "$(repo k v1.2.3 'fix: bug')"                             1.2.3 auto
expect "feat"                 1.3.0 "$(repo l v1.2.3 'feat: thing')"                          1.2.3 auto
expect "feat!"                2.0.0 "$(repo m v1.2.3 'feat!: drop')"                          1.2.3 auto
expect "BREAKING-CHANGE body" 2.0.0 "$(repo n v1.2.3 $'fix: x\n\nBREAKING-CHANGE: y')"        1.2.3 auto

echo "history before the base tag is ignored"
expect "old feat! not counted" 0.2.1 "$(repo o v0.2.0 'fix: later')" 0.2.0 auto
dir="$(repo p '' 'feat!: ancient')"; git -C "$dir" tag v0.2.0; git -C "$dir" commit -q --allow-empty -m 'fix: later'
expect "breaking before tag"   0.2.1 "$dir" 0.2.0 auto

echo "no tag yet: whole history"
expect "untagged"             0.3.0 "$(repo q '' 'feat: first')"                              0.2.0 auto

echo "manual"
dir="$(repo r v0.2.0)"
expect "patch" 0.2.1 "$dir" 0.2.0 patch
expect "minor" 0.3.0 "$dir" 0.2.0 minor
expect "major" 1.0.0 "$dir" 0.2.0 major
expect "bad bump"    FAIL "$dir" 0.2.0 huge
expect "bad version" FAIL "$dir" v0.2  auto

if [ "$failed" -eq 0 ]; then
  echo "all passed"
else
  echo "FAILED"
  exit 1
fi
