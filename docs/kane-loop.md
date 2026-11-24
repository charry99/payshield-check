# The Kane loop

How Kane CLI and the coding agent talk to each other in this project — the
closed loop the hackathon scores.

1. **Author flows in plain English.** The three flows in `tests/` describe
   what a user does and what must be visible afterwards (verdict text, reasons,
   error message). No selectors, no scripts — Kane drives a real cloud browser
   and reads the page like a user would.
2. **Run them headless.** `./scripts/verify.sh` sets the app URL with
   `kane-cli config set-url` and runs `kane-cli testrun run --headless tests/`.
   Exit 0 = all flows passed, 1 = at least one failed. Every run seals a
   `.evidence` file (steps, screenshots, video, logs) viewable at
   evidence.lambdatest.com.
3. **Feed failures back to the agent.** On a fail, the evidence pack and the
   failing step are handed to the coding agent with the failing assertion.
   The agent fixes the app (not the test), the fix is committed, and the flows
   re-run until they pass. The bug, the fix, and the re-run result are
   recorded in the README's "Bugs Kane caught" section.
4. **CI keeps the loop honest.** `.github/workflows/kane.yml` runs the same
   flows on every push to `main` (gated on the TestMu repo secrets, so the
   job skips cleanly when they are not set). A failing Kane run blocks the
   merge; the fix loop in step 3 is what unblocks it.
5. **The demo shows the loop.** The YouTube demo walks through one flow
   passing, and — if Kane catches a real bug during the build — the bug, the
   fix, and the passing re-run.
