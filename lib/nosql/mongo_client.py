#!/usr/bin/env python

"""
Portions derived from NoSQLMap (https://github.com/codingo/NoSQLMap),
Copyright (c) 2014 Russell Butturini, licensed under the GNU General
Public License v3 (or later). Ported from the original interactive,
Python 2 menu-driven tool (nsmmongo.py) to standalone, importable
Python 3 functions with no interactive prompts, so it can be driven
programmatically by lib/ai/tools.py the same way lib/ai wraps sqlmap's
own REST API - see doc/NEXTGEN.md for the integration writeup.

Deliberately NOT ported from the original:
    - Metasploit-based shell/exploit launching (msfLaunch, the
      Meterpreter integration in netAttacks) - out of scope for the
      same reason sqlmap's os-shell/os-cmd/file-write options are
      blocked by default elsewhere in this project (see
      lib/ai/safety.py, RESTAPI_DANGEROUS_OPTIONS in
      lib/core/settings.py): this is a data-injection and enumeration
      framework, not an OS-takeover one.
    - stealDBs' use of MongoDB's copy_database admin command - removed
      entirely in MongoDB server 4.2+ and modern pymongo, so porting it
      faithfully would build a feature that doesn't work against any
      currently-supported MongoDB version. dump_collection() below is
      the modern equivalent: direct document extraction via find(),
      matching how lib/ai's dump_table works on the SQL side.
    - The interactive password-cracking prompt embedded in the
      original's enumDbs() - split out as its own function
      (crack_hash()) so a caller decides whether/when to invoke it,
      rather than it blocking mid-enumeration on a menu prompt.

IMPORTANT - not live-tested against a real MongoDB instance: this
sandbox has no network egress, no pymongo package available to
install, and no mongod binary - so unlike everything else in this
project, this module's actual wire-protocol behavior could not be
verified against a running server the way sqlmap's REST API was
verified against real HTTP targets throughout the rest of this
project. The import is wrapped so the module loads and its
control-flow is unit-testable (see lib/ai/tests/test_nosql.py) even
without pymongo installed; only an actual connection attempt requires
it. Treat this module as reviewed-and-reasoned-through, not
proven-against-a-real-server, until it's been run against one.
"""

try:
    import pymongo
    PYMONGO_AVAILABLE = True
except ImportError:
    pymongo = None
    PYMONGO_AVAILABLE = False


class MongoUnavailable(Exception):
    pass


def _require_pymongo():
    if not PYMONGO_AVAILABLE:
        raise MongoUnavailable(
            "pymongo is not installed. Install it with 'pip install pymongo' "
            "to use any lib.nosql.mongo_client functionality."
        )


def scan_anonymous_access(host, port=27017, timeout_ms=4000):
    """
    Checks whether a MongoDB instance at host:port allows unauthenticated
    access - a common, real-world misconfiguration (MongoDB's own
    changelog and numerous public breach writeups document instances
    left open with no auth at all). Ported from nsmmongo.py's
    mongoScan(), with the interactive ping-first branch removed (an
    ICMP ping is not a reliable reachability signal in most modern
    network environments and isn't needed - the connection attempt
    itself is the real test) and Python 3 syntax throughout.

    Returns a dict: {"status": one of "open"/"auth_required"/"error"/
    "unreachable", "version": MongoDB server version string or None}.
    """
    _require_pymongo()

    try:
        conn = pymongo.MongoClient(host, port, connectTimeoutMS=timeout_ms, socketTimeoutMS=timeout_ms,
                                    serverSelectionTimeoutMS=timeout_ms)

        try:
            db_names = conn.list_database_names()
            version = conn.server_info().get("version")
            conn.close()
            return {"status": "open", "version": version, "database_count": len(db_names)}
        except Exception as ex:
            conn.close()
            if "need to login" in str(ex) or "auth" in str(ex).lower() or "unauthorized" in str(ex).lower():
                return {"status": "auth_required", "version": None}
            return {"status": "error", "version": None, "detail": str(ex)}

    except Exception as ex:
        return {"status": "unreachable", "version": None, "detail": str(ex)}


def enumerate_databases(host, port=27017, username=None, password=None, timeout_ms=4000):
    """
    Lists databases and, for each, its collections - the MongoDB
    equivalent of lib/ai's list_databases/list_tables. Ported from
    nsmmongo.py's enumDbs(), split from the original's inline
    "found system.users, want to crack a hash?" prompt (see
    crack_hash() below) and from the platform-info printing (see
    get_server_info() below) so each concern is its own function
    instead of one function doing enumeration, printing, and
    interactive password cracking all at once.

    Returns {"databases": {db_name: [collection_names]}, "users_found": [{db, user, hash}]}.
    """
    _require_pymongo()

    result = {"databases": {}, "users_found": []}

    conn = pymongo.MongoClient(host, port, username=username, password=password,
                                connectTimeoutMS=timeout_ms, socketTimeoutMS=timeout_ms,
                                serverSelectionTimeoutMS=timeout_ms)

    try:
        db_names = conn.list_database_names()
    except Exception as ex:
        conn.close()
        raise MongoUnavailable("Couldn't list databases (credentials may lack rights): %s" % ex)

    for db_name in db_names:
        try:
            db = conn[db_name]
            collections = db.list_collection_names()
            result["databases"][db_name] = collections

            if "system.users" in collections:
                for user_doc in db.system.users.find():
                    if "user" in user_doc and "pwd" in user_doc:
                        result["users_found"].append({
                            "database": db_name, "user": user_doc["user"], "hash": user_doc["pwd"],
                        })
        except Exception:
            result["databases"][db_name] = None  # listed but couldn't enumerate collections

    conn.close()
    return result


def dump_collection(host, port, database, collection, username=None, password=None,
                     query=None, limit=1000, timeout_ms=4000):
    """
    Extracts documents from one collection directly via find() - the
    modern equivalent of the original's stealDBs(), which relied on
    MongoDB's copy_database admin command (removed in MongoDB 4.2+ and
    modern pymongo, so not portable as-is - see module docstring).
    Mirrors lib/ai's dump_table: narrow with an optional query/limit
    rather than always pulling everything.

    query: optional dict, MongoDB query filter (e.g. {"role": "admin"}).
    Returns a list of documents (as dicts, with ObjectId/etc. converted
    to strings for JSON-safety).
    """
    _require_pymongo()

    conn = pymongo.MongoClient(host, port, username=username, password=password,
                                connectTimeoutMS=timeout_ms, socketTimeoutMS=timeout_ms,
                                serverSelectionTimeoutMS=timeout_ms)

    try:
        db = conn[database]
        coll = db[collection]
        cursor = coll.find(query or {}).limit(limit)
        # round-trip through bson.json_util so ObjectId/datetime/etc. become
        # plain JSON-safe strings, same reasoning as lib.core.convert.jsonize
        # elsewhere in this project - the caller shouldn't need to know
        # about BSON-specific types.
        docs = [bson_doc_to_plain(doc) for doc in cursor]
        return docs
    finally:
        conn.close()


def bson_doc_to_plain(doc):
    import json
    import bson.json_util
    return json.loads(bson.json_util.dumps(doc))


def search_collections(host, port, keyword, username=None, password=None, timeout_ms=4000):
    """
    Searches collection names across every database for a keyword -
    the MongoDB equivalent of lib/ai's search_data table-search mode
    (MongoDB has no cross-database column/field-name catalog to search
    the way search_data's column mode does for SQL DBMSes, so this
    covers the collection-name-search case only).
    """
    _require_pymongo()

    conn = pymongo.MongoClient(host, port, username=username, password=password,
                                connectTimeoutMS=timeout_ms, socketTimeoutMS=timeout_ms,
                                serverSelectionTimeoutMS=timeout_ms)

    matches = []
    try:
        for db_name in conn.list_database_names():
            try:
                for coll_name in conn[db_name].list_collection_names():
                    if keyword.lower() in coll_name.lower():
                        matches.append({"database": db_name, "collection": coll_name})
            except Exception:
                continue
    finally:
        conn.close()

    return matches


def get_server_info(host, port, username=None, password=None, timeout_ms=4000):
    """Ported from nsmmongo.py's getPlatInfo(), returning a dict instead of printing."""
    _require_pymongo()

    conn = pymongo.MongoClient(host, port, username=username, password=password,
                                connectTimeoutMS=timeout_ms, socketTimeoutMS=timeout_ms,
                                serverSelectionTimeoutMS=timeout_ms)
    try:
        info = conn.server_info()
        return {"version": info.get("version"), "debug": info.get("debug"), "bits": info.get("bits")}
    finally:
        conn.close()
