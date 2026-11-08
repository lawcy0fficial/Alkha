# Licensing and rebrand compliance guide

This consolidates everything relevant to redistributing, rebranding, or
commercializing this project into one place. It restates facts already
established in `LICENSE`, `doc/THIRD-PARTY.md`, and `doc/ALKHA.md` §13-14
(read those for the full reasoning) - this document exists so you have a
single checklist to work from, or to hand to a lawyer, without needing to
reconstruct the reasoning from scattered dev-log entries.

**This is not legal advice.** It's an accurate summary of what the licenses
in this repository say and how they interact, written by the tool that did
the engineering work, not by a lawyer. Anything below marked "consult a
lawyer" is a genuine, non-trivial open question - don't treat this document
as a substitute for actually doing that before money or a public closed-
source release is involved.

## 1. What this project actually is, license-wise

Three distinct bodies of code, three different licenses, combined into one
distributed program:

| Component | License | Where |
|---|---|---|
| sqlmap engine (detection/exploitation core, unmodified) | GPLv2-or-later | everywhere outside `lib/ai/`, `lib/nosql/` |
| NoSQLMap-derived code | GPLv3-or-later | `lib/nosql/mongo_client.py` specifically (see §2) |
| This project's own original additions (agent, tools, safety, UI) | GPLv3-or-later, your choice as the author | `lib/ai/`, most of `lib/nosql/`, `lib/core/tui.py`, `alkha_agent.py`, `api_bootstrap.py` |
| Bundled third-party libraries | BSD / LGPL / PSF / MIT / public domain, per-library | `thirdparty/`, `extra/icmpsh/` - full list in `doc/THIRD-PARTY.md`, verified against the actual directory contents (18 libraries + icmpsh, all accounted for, no discrepancies found) |

**Governing license for the combined, distributed program: GPLv3.** A
GPLv2-*or-later* work (sqlmap) may be used under GPLv3 terms; GPLv3-or-later
code (the NoSQLMap-derived portion) cannot be downgraded to GPLv2. When you
combine both into one distributed program, the combination must satisfy the
more restrictive of the two, which is GPLv3. This is why `LICENSE` and the
README's license badge both say GPLv3 (alongside GPLv2-or-later for
attribution accuracy on the sqlmap portion specifically).

## 2. Where NoSQLMap's code actually is - this matters for §4 below

Not all of `lib/nosql/` carries NoSQLMap's copyright - only the part that's
actually derived from it:

- **`lib/nosql/mongo_client.py`** - a direct port of NoSQLMap's
  `nsmmongo.py` (interactive Python 2 → standalone Python 3 functions).
  Carries NoSQLMap's copyright notice in its module docstring: *"Portions
  derived from NoSQLMap (https://github.com/codingo/NoSQLMap), Copyright
  (c) 2014 Russell Butturini, licensed under the GNU General Public
  License v3 (or later)."* This file is bound by NoSQLMap's GPLv3-or-later
  terms specifically.
- **`lib/nosql/injection_probe.py`** - independently written. Its docstring
  explains why: it implements the same *technique class* NoSQLMap's
  `getApps()`/`postApps()` use (both ultimately credit the same public
  research - Ming Chow's DEF CON 21 talk), but is not a port of NoSQLMap's
  actual code, which is ~1700 lines tightly coupled to interactive
  `raw_input()` prompts this project has no equivalent of. No NoSQLMap
  copyright notice on this file because none is owed - it doesn't contain
  NoSQLMap's code.
- Everything else under `lib/ai/` (the agent, tools, safety policy, memory,
  planner, UI) is original work with no NoSQLMap or sqlmap-engine lineage.

This distinction is not pedantic - it's the entire basis for §4's answer
being "it depends which file" rather than a single yes/no.

## 3. What you can freely do right now

- Keep building, keep it open source, keep the current GPLv3 licensing.
- Redistribute it, including under the Alkha name, as long as `LICENSE`,
  `doc/THIRD-PARTY.md`, and every existing copyright header stay intact.
  Renaming the *project* doesn't require touching any of those.
- Modify anything, including the sqlmap engine itself - GPL explicitly
  permits derivative works, provided source stays available under the
  same terms to whoever you distribute the binary/program to.
- Charge money for services around it (support contracts, hosted scanning,
  training, consulting) - the GPL restricts what license you can distribute
  the *software* under, not what you can charge for services involving it.
- Distribute it as source code the way it already is (a git-style
  repository/zip of `.py` files) - this trivially satisfies GPL's source-
  availability requirement, since the source *is* the distributed form.

## 4. What you cannot do without further action

**You cannot relicense the combined project as closed-source/proprietary**
without resolving both of the following independently - resolving one does
NOT resolve the other:

- **The sqlmap-engine portion**: `LICENSE` explicitly offers a way out -
  *"If you wish to embed sqlmap technology into proprietary software, we
  sell alternative licenses (contact sales@sqlmap.org)."* This is the
  documented, intended path for the engine itself.
- **The NoSQLMap-derived portion** (`lib/nosql/mongo_client.py`
  specifically, per §2): NoSQLMap's GPLv3-or-later license, as stated in
  its copyright notice, offers no such commercial-buyout mechanism that
  this project is aware of. Buying a commercial sqlmap license from
  sqlmap.org does **not** clear this file - it only addresses the engine.
  As long as `mongo_client.py` contains NoSQLMap-derived code, distributing
  it as part of a closed-source product would require one of:
  1. Written permission from NoSQLMap's copyright holder (Russell
     Butturini) to relicense that specific derived work, or
  2. Removing `lib/nosql/mongo_client.py` (the direct-MongoDB-connection
     enumeration/dump functions) from the closed variant - note this
     does *not* require removing `lib/nosql/injection_probe.py`, per §2's
     distinction, since that file owes no debt to NoSQLMap's code, or
  3. A clean-room rewrite of the same functionality with no reference to
     NoSQLMap's implementation, written by someone who has not read
     NoSQLMap's source (a real clean-room process, not just "written
     independently while having read the original" - the latter doesn't
     reliably avoid derivative-work status).

**Consult a lawyer before acting on this section specifically** - whether
option 3 above actually clears the derivative-work concern in your
jurisdiction, and how to actually reach and negotiate with a NoSQLMap
copyright holder for option 1, are real open questions this document
can't resolve for you.

## 5. Trademark and naming

`LICENSE` defines "derived work" broadly for sqlmap's own purposes (see the
file directly for the full list: integrating source, reading sqlmap's
copyrighted data files, executing sqlmap and parsing results, etc.) but
does not itself impose trademark restrictions on the name "sqlmap" beyond
copyright law. Two separate, practical points:

- This project already avoids implying official endorsement - the README
  is explicit that this is *"a fork of the open source penetration testing
  tool sqlmap,"* not sqlmap itself, and the classic banner/version string
  still correctly attributes the underlying engine to sqlmap by name (an
  attribution *requirement*, not just courtesy - see `lib/core/tui.py`'s
  `render_banner()` docstring).
- Whether "sqlmap" or "sqlmap developers" is a registered trademark
  anywhere, separate from copyright, isn't something this document can
  verify - if you plan wide public distribution or paid offerings under
  the Alkha name, a trademark search/clearance for both "Alkha" and
  confirming your use of "sqlmap" in descriptive text stays non-infringing
  is a reasonable, low-cost thing to have a lawyer glance at alongside §4.

## 6. Practical GPLv3 compliance checklist for any release

- [ ] `LICENSE` file included, unmodified, alongside every distribution.
- [ ] `doc/THIRD-PARTY.md` included, unmodified, alongside every
      distribution (verified accurate against `thirdparty/`'s actual
      contents as of this writing - re-verify if you add/remove any
      bundled library before your next release).
- [ ] Every source file's existing copyright header stays intact - this
      includes the NoSQLMap notice in `mongo_client.py` specifically.
- [ ] If you distribute a *binary* (a compiled/frozen executable, a
      Docker image, anything that isn't the raw `.py` source a recipient
      could directly read and modify), you must also make the
      Corresponding Source available to whoever receives the binary -
      distributing source-form the way this repository already is
      side-steps this requirement entirely, which is the simplest
      compliance posture if you have no specific reason to ship binaries.
- [ ] Any modification you make and then distribute must itself carry a
      notice that you changed it (GPLv3 §5) - a dated changelog entry or
      a comment at the point of change satisfies this; this repository's
      existing pattern of dated dev-log-style docstrings/comments already
      does this for changes made so far.
- [ ] If you add a NEW third-party dependency (vendored code, not just an
      optional runtime import like `pymongo`), add it to
      `doc/THIRD-PARTY.md` in the same format as the existing entries
      before your next distribution.

## 7. If you ever want a genuinely closed-source commercial variant

Given §4, the realistic paths, roughly ordered by effort:

1. **Cleanest**: ship a variant with `lib/nosql/mongo_client.py` removed
   (direct-MongoDB enumeration/dump goes away; `injection_probe.py`'s
   HTTP-based operator/`$where` injection testing stays, since it owes
   nothing to NoSQLMap) + a purchased sqlmap commercial license from
   sqlmap.org for the engine. No permission-seeking required, no clean-
   room process needed - just scoping the closed variant to exclude the
   one file with an unresolved license.
2. **More capability, more effort**: pursue option 1 or 3 from §4 for
   `mongo_client.py` specifically (permission or clean-room rewrite),
   *in addition to* the sqlmap commercial license for the engine.
3. Keep the full-featured version GPLv3 (this repository's current
   state) and monetize via §3's paths (services, support, hosting)
   instead of a closed-source product license.
