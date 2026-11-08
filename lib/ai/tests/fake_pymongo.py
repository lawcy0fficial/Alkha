#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission

A small in-memory stand-in for `pymongo` (and the sliver of `bson` that
lib/nosql/mongo_client.py uses), so that module's actual logic - which
databases/collections get reported, how anonymous-access and
auth-required are told apart, how a `find()`+`limit()` query narrows
results, how per-database enumeration failures are handled - can be
exercised without a real `mongod` binary or the `pymongo` package,
neither of which are available in this sandbox (no network egress to
install anything, no MongoDB binary present).

BE HONEST ABOUT WHAT THIS IS AND ISN'T:
This is NOT a substitute for testing against a real MongoDB server.
It reimplements just enough of pymongo's Python-level API surface
(MongoClient, list_database_names, list_collection_names, find,
server_info, close) to drive mongo_client.py's own control flow and
catch logic bugs in THIS project's code - it proves nothing about
actual MongoDB wire-protocol behavior, real auth failure modes, real
BSON edge cases, or anything pymongo itself might do differently than
this fake. Treat a pass here as "the logic is exercised and behaves as
intended against a plausible fake," not as "verified against a real
server" - lib/nosql/mongo_client.py's own module docstring is explicit
about carrying this same caveat.

Usage (see lib/ai/tests/test_mongo_client_fake_server.py):

    from lib.ai.tests.fake_pymongo import FakeMongoEnvironment
    with FakeMongoEnvironment(databases={...}) as env:
        # lib.nosql.mongo_client is (re)imported here with sys.modules
        # already patched, so `import pymongo` inside it resolves to
        # this fake instead of failing/using a real install.
        from lib.nosql import mongo_client
        ...
"""

import copy
import json
import sys
import types


class FakeConnectionError(Exception):
    pass


class FakeOperationFailure(Exception):
    pass


class _FakeCursor(object):
    def __init__(self, docs):
        self._docs = list(docs)
        self._limit = None

    def limit(self, n):
        self._limit = n
        return self

    def __iter__(self):
        docs = self._docs if self._limit is None else self._docs[:self._limit]
        return iter(docs)


class _FakeCollection(object):
    def __init__(self, docs, db=None, name=None):
        self._docs = docs
        self._db = db
        self._name = name

    def find(self, query=None):
        query = query or {}
        matched = [d for d in self._docs if _matches(d, query)]
        return _FakeCursor(matched)

    def __getattr__(self, attr):
        # mirrors real pymongo's Collection.__getattr__, which is what makes
        # `db.system.users` resolve to the dotted collection "system.users"
        # rather than an attribute lookup on the "system" collection object -
        # mongo_client.py's enumerate_databases() relies on exactly this.
        if attr.startswith("_"):
            raise AttributeError(attr)
        if self._db is None or self._name is None:
            raise AttributeError(attr)
        return self._db[self._name + "." + attr]


def _matches(doc, query):
    for key, expected in query.items():
        if key not in doc or doc[key] != expected:
            return False
    return True


class _FakeDatabase(object):
    def __init__(self, name, spec):
        self.name = name
        self._collections = spec.get("collections", {})

    def list_collection_names(self):
        if self._collections is None:  # simulates "listed but can't enumerate"
            raise FakeOperationFailure("not authorized to enumerate collections on %s" % self.name)
        return list(self._collections.keys())

    def __getitem__(self, collection_name):
        docs = (self._collections or {}).get(collection_name, [])
        return _FakeCollection(docs, db=self, name=collection_name)

    def __getattr__(self, name):
        # supports the `db.system.users.find(...)` attribute-access style
        # mongo_client.py uses, in addition to the __getitem__ style
        return self[name]


class FakeMongoClient(object):
    """
    Stands in for pymongo.MongoClient. Constructor accepts (and ignores,
    same as the real driver would just use them for connection setup)
    the keyword arguments mongo_client.py passes - connectTimeoutMS,
    socketTimeoutMS, serverSelectionTimeoutMS - plus username/password,
    which this fake DOES check against the seeded environment so
    auth-required/auth-failure code paths are exercisable too.
    """

    def __init__(self, host, port=27017, username=None, password=None, **kwargs):
        env = _CURRENT_ENV[0]
        if env is None:
            raise FakeConnectionError("no FakeMongoEnvironment installed")

        self.host, self.port = host, port
        self.closed = False

        if env.requires_auth and not (username == env.valid_username and password == env.valid_password):
            self._authorized = False
        else:
            self._authorized = True

        self._env = env

    def list_database_names(self):
        if not self._authorized:
            raise FakeOperationFailure("command listDatabases requires authentication, need to login")
        return list(self._env.databases.keys())

    def server_info(self):
        if not self._authorized:
            raise FakeOperationFailure("command buildInfo requires authentication, need to login")
        return dict(self._env.server_info)

    def __getitem__(self, db_name):
        if db_name not in self._env.databases:
            # real pymongo lazily creates an empty logical handle rather than
            # raising here - mirror that; absence only surfaces on use.
            return _FakeDatabase(db_name, {"collections": {}})
        return _FakeDatabase(db_name, self._env.databases[db_name])

    def close(self):
        self.closed = True


class FakeMongoEnvironment(object):
    """
    Context manager that installs fake `pymongo` (and the sliver of
    `bson.json_util` mongo_client.py's bson_doc_to_plain() needs) into
    sys.modules, seeds them with the given fixture data, and forces a
    fresh (re)import of lib.nosql.mongo_client so its `import pymongo` /
    `PYMONGO_AVAILABLE` reflect the fake rather than whatever real state
    existed before. Restores the previous sys.modules state on exit.

    databases: {db_name: {"collections": {coll_name: [doc, ...]}}}
               a collections value of None simulates "database is
               listed but enumerating its collections fails" (e.g. a
               permissions edge case) - see mongo_client.py's own
               per-database try/except for why that matters.
    requires_auth / valid_username / valid_password: simulate a
               credentialed instance, to exercise the auth-required
               detection path in scan_anonymous_access().
    """

    def __init__(self, databases=None, server_info=None, requires_auth=False,
                 valid_username=None, valid_password=None):
        self.databases = databases or {}
        self.server_info = server_info or {"version": "7.0.0-fake", "debug": False, "bits": 64}
        self.requires_auth = requires_auth
        self.valid_username = valid_username
        self.valid_password = valid_password

        self._prev_modules = {}
        self._prev_env_slot = None

    def __enter__(self):
        _CURRENT_ENV[0] = self

        fake_pymongo = types.ModuleType("pymongo")
        fake_pymongo.MongoClient = FakeMongoClient
        fake_pymongo.errors = types.ModuleType("pymongo.errors")
        fake_pymongo.errors.OperationFailure = FakeOperationFailure
        fake_pymongo.errors.ConnectionFailure = FakeConnectionError

        fake_bson = types.ModuleType("bson")
        fake_json_util = types.ModuleType("bson.json_util")
        fake_json_util.dumps = lambda doc: json.dumps(doc, default=str)
        fake_bson.json_util = fake_json_util

        for name, mod in (("pymongo", fake_pymongo), ("pymongo.errors", fake_pymongo.errors),
                           ("bson", fake_bson), ("bson.json_util", fake_json_util)):
            self._prev_modules[name] = sys.modules.get(name)
            sys.modules[name] = mod

        # force lib.nosql.mongo_client to re-evaluate its module-level
        # `import pymongo` against the fake we just installed
        self._prev_mongo_client_module = sys.modules.pop("lib.nosql.mongo_client", None)

        # `from lib.nosql import mongo_client` resolves via getattr() on the
        # already-imported "lib.nosql" package *before* it ever consults
        # sys.modules - if some earlier import (e.g. another test module)
        # already set that attribute, popping sys.modules alone is not
        # enough to force a fresh import; the attribute itself has to go.
        parent = sys.modules.get("lib.nosql")
        self._had_parent_attr = parent is not None and "mongo_client" in vars(parent)
        if self._had_parent_attr:
            self._prev_parent_attr = parent.mongo_client
            delattr(parent, "mongo_client")

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for name, mod in self._prev_modules.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod

        sys.modules.pop("lib.nosql.mongo_client", None)
        if self._prev_mongo_client_module is not None:
            sys.modules["lib.nosql.mongo_client"] = self._prev_mongo_client_module

        parent = sys.modules.get("lib.nosql")
        if parent is not None:
            if self._had_parent_attr:
                parent.mongo_client = self._prev_parent_attr
            else:
                # a fresh import during the `with` block may have set the
                # attribute where none existed before - remove it so a
                # subsequent real (non-fake) import isn't shadowed by it.
                if "mongo_client" in vars(parent) and self._prev_mongo_client_module is None:
                    delattr(parent, "mongo_client")

        _CURRENT_ENV[0] = None
        return False

    def snapshot(self):
        return copy.deepcopy(self.databases)


# a single-slot "current environment" so FakeMongoClient (constructed deep
# inside mongo_client.py, with no way for us to inject it as an argument)
# can find whichever environment is currently active
_CURRENT_ENV = [None]
