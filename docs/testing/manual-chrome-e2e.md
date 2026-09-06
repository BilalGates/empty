# Chrome loaded-extension E2E

Build `apps/extension/dist`, start the fixture server, and launch a dedicated Chrome profile with the unpacked extension. Verify exact-origin suggestions and fill on traditional, SPA, dynamically inserted, signup, and password-change forms. Verify no suggestion or fill on lookalike origins and no secret delivery before selection.

Lock manually and through TTL, then confirm content scripts cannot retrieve credentials. Inspect service-worker storage and logs for plaintext. Record Chrome/OS version, artifact hash, failures, and screenshots without secrets. Remove the disposable profile after the run.

