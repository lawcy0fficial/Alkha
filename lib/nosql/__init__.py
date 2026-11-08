#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
Portions Copyright (c) 2014 Russell Butturini (NoSQLMap), GPLv3-or-later
See doc/NEXTGEN.md for the integration writeup and licensing notes.

lib.nosql
---------
NoSQL (MongoDB) injection and misconfiguration testing, added alongside
the existing SQL-focused engine so this project covers both classes of
injection rather than SQL alone.

    mongo_client.py     - direct MongoDB connection: anonymous-access
                           detection, enumeration, targeted dumping.
                           Ported from NoSQLMap's nsmmongo.py. NOT
                           live-tested in this environment (no pymongo,
                           no network egress, no mongod available) -
                           see the module docstring.
    injection_probe.py  - operator/$where injection probing against
                           MongoDB-backed web apps. Freshly written
                           (not ported), stdlib-only, live-tested
                           against two real vulnerable targets.
"""
