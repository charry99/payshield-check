---
url: https://charry99.github.io/payshield-check/
tags: [invalid-input, error-handling]
---

# Invalid input — garbage text shows a clean error and the app does not crash

1. Open the app at the start URL.
2. Type `not a url at all` into the link input.
3. Click the "Check link" button.
4. Verify an error message is shown saying the input does not look like a link.
5. Verify no verdict card is shown.
6. Clear the input, type `https://pancakeswap.finance/`, and click the "Check link" button.
7. Verify the verdict card appears and reads "Safe" — the app recovered after the error.
