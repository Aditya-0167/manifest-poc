name: ext4-crash-poc
# marker: v2-no-workdir -- if you see this comment after pasting, you have the right file

# Manual trigger: go to the Actions tab in your repo, select this workflow,
# click "Run workflow". Also runs automatically on push, for convenience.
#
# This runs the actual crash reproduction on a real, Apple-hosted macOS
# runner (GitHub's macos-26 image, Xcode 26.6 as of 2026-07-21) -- this is
# the piece that cannot be done without physical/cloud Apple hardware, and
# it's the specific thing Apple Product Security asked to see for
# OE1107563755116: "a working proof of concept that demonstrates the crash
# on a current macOS build".
#
# Each PoC image is EXPECTED to crash its run -- that's the bug being
# demonstrated. The job is deliberately structured so one crashing step
# doesn't stop the rest from running, and the full output (including the
# actual Swift "Fatal error" trap text) ends up in both the workflow log
# and the job summary.

on:
  workflow_dispatch:
  push:
    branches: [main]

jobs:
  reproduce:
    runs-on: macos-26
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Show environment
        run: |
          sw_vers
          xcodebuild -version
          swift --version

      - name: Build harness
        run: swift build

      - name: Run all PoC images
        run: |
          LOG="poc-results.log"
          : > "$LOG"

          {
            echo "## ext4-crash-poc results"
            echo
            echo '```'
          } | tee -a "$LOG" "$GITHUB_STEP_SUMMARY"

          BIN=".build/debug/ext4-crash-poc"
          images=(
            "poc.img:Bug 1 - getExtents entries overflow (file inode, depth=0)"
            "poc_root_construction.img:Bug 1 - getExtents entries overflow (root inode, crashes on open)"
            "poc_depth1.img:Bug 1b - getExtents depth==1 index-node branch"
            "poc_dirbug_recordlength.img:Bug 2a - getDirEntries record-length gap"
            "poc_dirbug_namelength.img:Bug 2b - getDirEntries nameLength gap"
          )

          for entry in "${images[@]}"; do
            img="${entry%%:*}"
            desc="${entry#*:}"
            {
              echo
              echo "--- $img ($desc) ---"
            } | tee -a "$LOG" "$GITHUB_STEP_SUMMARY"

            set +e
            output=$("$BIN" "$img" 2>&1)
            status=$?
            set -e

            echo "$output" | tee -a "$LOG" "$GITHUB_STEP_SUMMARY"

            if [ $status -eq 0 ]; then
              echo "RESULT: FAIL (exited cleanly -- did not crash)" | tee -a "$LOG" "$GITHUB_STEP_SUMMARY"
            else
              echo "RESULT: PASS (crashed as expected, exit status $status)" | tee -a "$LOG" "$GITHUB_STEP_SUMMARY"
            fi
          done

          echo '```' >> "$GITHUB_STEP_SUMMARY"
          # Exit 0 regardless of individual crashes -- "the images crashed"
          # is a PASS for our purposes, not a CI failure. Per-image results
          # are visible above and in poc-results.log.
          exit 0

      - name: Upload full log as artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ext4-crash-poc-macos-log
          path: poc-results.log

      - name: Capture symbolicated backtraces (lldb)
        if: always()
        run: |
          LOG="poc-backtraces.log"
          : > "$LOG"

          {
            echo "## ext4-crash-poc backtraces (lldb)"
            echo
            echo "Each image is run under lldb. A REAL crash shows a stopped"
            echo "thread with a backtrace naming the crashing function (e.g."
            echo "EXT4.EXT4Reader.getExtents, Data.subdata, etc). If an image"
            echo "did not crash, lldb will report the process exited instead."
            echo
            echo '```'
          } | tee -a "$LOG" "$GITHUB_STEP_SUMMARY"

          BIN=".build/debug/ext4-crash-poc"
          images=(
            "poc.img:Bug 1 - getExtents entries overflow (file inode, depth=0)"
            "poc_root_construction.img:Bug 1 - getExtents entries overflow (root inode, crashes on open)"
            "poc_depth1.img:Bug 1b - getExtents depth==1 index-node branch"
            "poc_dirbug_recordlength.img:Bug 2a - getDirEntries record-length gap"
            "poc_dirbug_namelength.img:Bug 2b - getDirEntries nameLength gap"
          )

          for entry in "${images[@]}"; do
            img="${entry%%:*}"
            desc="${entry#*:}"
            {
              echo
              echo "--- $img ($desc) ---"
            } | tee -a "$LOG" "$GITHUB_STEP_SUMMARY"

            set +e
            lldb_out=$(lldb -b \
              -o "run" \
              -o "bt all" \
              -o "quit" \
              -- "$BIN" "$img" 2>&1)
            set -e

            echo "$lldb_out" | tee -a "$LOG" "$GITHUB_STEP_SUMMARY"
          done

          echo '```' >> "$GITHUB_STEP_SUMMARY"
          exit 0

      - name: Upload backtrace log as artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ext4-crash-poc-backtraces
          path: poc-backtraces.log
