# Roadmap

The roadmap records direction, not promises or dates. A GitHub issue with an
accepted problem statement and security analysis is required before work begins.

## Candidate follow-ups

- Stable Task and Goal schema v1 after field experience and compatibility fixtures.
- Structured lifecycle events and redaction-aware output sinks.
- Explicit process-tree termination semantics per supported platform.
- Optional adapters for established tool and model protocols.
- Signed manifest/provenance verification at the control-plane boundary.
- Reference isolation profiles for containers and microVMs.
- Reproducible release artifacts and provenance attestations.
- Windows journal locking and atomic durability semantics.
- Required branch-check rules that hold auto-merge until CI and CodeQL finish;
  PR #1 showed that auto-merge intent alone does not provide this gate.

Requests should be filed with the feature-request issue form. The v0 runtime
will remain intentionally small while these contracts are evaluated.
