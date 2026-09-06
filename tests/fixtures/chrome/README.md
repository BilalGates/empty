# Chrome fixtures

Serve this directory over localhost (never open the files directly) and use the unpacked extension against each page. The set covers traditional, SPA navigation, dynamically inserted forms, signup, password change, multi-account selection, iframe isolation, and lookalike-origin rejection.

The iframe fixture intentionally expects no top-frame fill inside the child frame: the production injection uses `allFrames: false`. Hostname lookalike testing requires mapping a local test hostname and HTTPS in the browser test harness.
