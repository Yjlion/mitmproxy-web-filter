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

- [ ] **2. Analytics dashboard** — aggregate the existing `logs/requests.jsonl`
  (action/component/policy/client_ip) into a UI page: top blocked domains,
  blocks over time, per-device breakdown, most-active categories. _~Low–medium._
  - Touches: new management API route, new/extended UI page. Data already logged.

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

## 🔵 Lower effort, narrower scope

- [ ] **7. Ad/tracker + malware blocking category** — reuse the existing
  category infra (`shared/categories.py`); mostly a data + updater-script change
  (`scripts/update_categories.sh`).

- [ ] **8. Search-query logging** — capture search terms (search URLs are
  already rewritten in `proxy/addons/safesearch.py`) for visibility/alerting.

---

**Recommended starting point:** #1 (scheduling — highest-impact feature) or
#2 (dashboard — fastest win, data already exists).
