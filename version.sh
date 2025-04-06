#!/bin/bash

set -e

remote_repo="https://github.com/sumwale/keepassxc-unlock"

if [ "$1" = "--remote" ]; then
  ls_remote=$(git ls-remote "$remote_repo")
  head_id=$(echo "$ls_remote" | awk '/[ \t]HEAD$/ { print $1 }')
  tags_with_id=$(echo "$ls_remote" | awk '{ if ($2 ~ /\^\{\}$/) { sub(/^.*\//, "", $2); tag = substr($2, 0, length($2) - 3); print $1 " " tag } }')
  latest_tag_with_id=$(echo "$tags_with_id" | sort -k2 -V | tail -n1)
  latest_tag=$(echo "$latest_tag_with_id" | awk '{ print $2 }')
  latest_tag_id=$(echo "$latest_tag_with_id" | awk '{ print $1 }')
else
  head_id=$(git rev-parse HEAD)
  latest_tag=$(git describe --tag --abbrev=0)
  latest_tag_id=$(git rev-list -n1 $latest_tag)
fi
if [ "$head_id" = "$latest_tag_id" ]; then
  echo "$latest_tag"
else
  echo "$latest_tag-$(git rev-parse --short HEAD)"
fi
