# TODO — Feature Ideas

Candidate features for the web filter, ranked by value-to-effort. Captured for
later; nothing here is committed to yet.

## 🟢 High value, low–medium effort (best starting points)

- [ ] **1. Time-based scheduling** — add a `schedule` block to `Policy`
  (e.g. block social media 21:00–07:00, internet off during school hours).
  `policy_router` already runs per-request and hot-reloads; it just needs to
  consult the clock when matching. _~Medium._
  - Touches: `shared/models.py` (new `ScheduleConfig`), `proxy/addons/policy_router.py`,
    policy editor UI, tests.

- [x] **2. Analytics dashboard** — ✅ Implemented. Aggregates `logs/requests.jsonl`
  and `logs/blocks.jsonl` into `management/ui/analytics.html` via `/api/analytics`:
  summary cards, top blocked domains, blocks by filter, blocks over time, and a
  per-device breakdown (windows up to 30 days).

- [ ] **3. Temporary override / "allow for 30 min"** — admin button (and
  optional "request access" link on the block page) granting a domain a
  time-boxed pass. Needs a small expiring-state store the addons check. _~Medium._

## 🟡 High value, medium effort

- [ ] **4. Alerts / notifications** — email or push when a device repeatedly
  hits blocked categories, or on specific flagged keywords. Builds on the log
  pipeline.

- [ ] **5. Block-page "request access" → approval queue** — kid clicks "ask a
  parent"; admin sees a queue in the UI and approves/denies. Pairs with #3.

- [ ] **6. Per-policy time budgets / quotas** — e.g. "1 hour of YouTube per
  day". Needs persistent per-device usage accounting.

- [ ] **9. Test-a-link page** — a `tester.html` admin page + nav item with two
  modes. _~Medium._ (Shelved; logging redesign goes first.)
  - **Mode 1 — Policy dry-run** (`POST /api/test/policy` with `{source_ip, url}`):
    report which policy matches (exact / CIDR / catch-all and why) and the
    request-side verdict (url_filter allow/block, category hit, safesearch
    rewrite, mitm passthrough) with the reason. Reuses `proxy/matching.py` and a
    pure refactor of `policy_router.get_policy`. Covers request-side only;
    response-side (classifiers, YouTube) can't be predicted from a URL alone.
  - **Mode 2 — Run a URL through the classifiers.** Architecture undecided:
    (A) classify in the mgmt API (httpx fetch + lazy-loaded NudeNet/text logic —
    simplest, but duplicates the model into a 2nd process and doesn't exercise
    the real pipeline); (B) "test mode" routed through the real proxy (forces a
    chosen policy, emits a verdict instead of mutating content — exact pipeline,
    more work, needs proxy CA trust for httpx). Open sub-questions: HTML pages =
    text-only vs also scan embedded images; run under a chosen policy's
    thresholds vs fixed defaults; SSRF surface (admin-only, auth-gated).

## 🔴 Filtering coverage gaps (close the bypasses)

- [ ] **10. QUIC / HTTP3 leak** — Chrome speaks QUIC (UDP/443) to Google and
  YouTube, which sidesteps an HTTP proxy entirely and quietly defeats YouTube
  filtering and safesearch. Mitigate by stripping the `Alt-Svc` response header
  to force fallback to TCP/TLS (cheap, addon-side), and/or document a firewall
  rule blocking outbound UDP/443. Without this, YouTube filtering is leaky on
  Chrome. _~Low (Alt-Svc strip) / docs._
  - Touches: a small response addon (or extend `request_logger`/a new
    `quic_block.py`), README deployment notes.

- [ ] **11. SNI-based blocking for non-MITM'd hosts** — hosts in
  `mitm.mode == "exclude"` currently can't be filtered at all (TLS not
  decrypted). Reading the TLS ClientHello SNI lets us still block by domain
  without decrypting, closing the "bypass TLS ⇒ bypass filter" hole. _~Medium._
  - Touches: a TLS-layer hook (`tls_clienthello`) in a new addon; checks the
    matched policy's block-list/categories against the SNI host.

## 🟡 Coverage & operational additions

- [ ] **12. More safesearch / restricted-mode targets** — YouTube Restricted
  Mode (inject `YouTube-Restrict: Strict` header), Bing/DuckDuckGo strict
  variants, and forcing SafeSearch on image-CDN hosts. Small, high-payoff
  additions to `proxy/addons/safesearch.py` + tests. _~Low._

- [ ] **13. Config backup & restore** — one-click export/import of all
  `policies/*.json` + `config/settings.json` as a single bundle. Generalizes the
  existing CA export/import in `management/api/routes/certs.py`. Makes migration
  and disaster-recovery trivial. _~Low–medium._

## 🔵 Lower effort, narrower scope

- [ ] **7. Ad/tracker + malware blocking category** — reuse the existing
  category infra (`shared/categories.py`); mostly a data + updater-script change
  (`scripts/update_categories.sh`).

- [ ] **8. Search-query logging** — capture search terms (search URLs are
  already rewritten in `proxy/addons/safesearch.py`) for visibility/alerting.

---

**Recommended starting point:** #1 (scheduling — highest-impact feature) or
#2 (dashboard — fastest win, data already exists).
