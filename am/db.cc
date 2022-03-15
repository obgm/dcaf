/*
 * db.cc -- Database handling for DCAF authorization manager
 *
 * Copyright (C) 2018-2021 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#include <iostream>
#include <iomanip>
#include <map>
#include <string>
#include <sstream>

#include "dcaf_config.h"

#ifdef HAVE_SQLITE
#include <sqlite3.h>
#endif /* HAVE_SQLITE */

#include "dcaf/dcaf.h"
#include "db.hh"

struct sqlite3;

namespace am {
using ::std::string;
using ::std::map;
using ::std::pair;

class Database::Implementation {
public:
  virtual ~Implementation(void) = default;
  virtual operator sqlite3 *(void) const { return nullptr; }

  virtual operator bool(void) const = 0;
  virtual const char *errmsg(void) const = 0;
};

#ifdef HAVE_SQLITE
class Database::SQLite : public Database::Implementation {
public:
  SQLite(const std::string &dbname, const std::string &vfs = std::string());

  ~SQLite(void) { if (db) { sqlite3_close_v2(db); db = nullptr; } }

  operator bool(void) const;
  const char *errmsg(void) const;

private:
  int status;
  sqlite3 *db;
};

Database::SQLite::SQLite(const std::string &dbname,
                         const std::string &vfs) {
  status = sqlite3_open_v2(dbname.c_str(),
                           &db,
                           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                           vfs.empty() ? nullptr : vfs.c_str());
  if (status != SQLITE_OK) {
    std::cerr << status << ": " << sqlite3_errmsg(db) << std::endl;
    db = nullptr;
  }
}

Database::SQLite::operator bool(void) const {
  return db && ((status == SQLITE_OK)
                || (status == SQLITE_DONE)
                || (status == SQLITE_ROW));
}

const char *Database::SQLite::errmsg(void) const {
  return db ? sqlite3_errmsg(db) : nullptr;
}
#endif /* HAVE_SQLITE */

static constexpr bool sqlite3 = 
#ifdef HAVE_SQLITE
  true;
#else /* !HAVE_SQLITE */
  false;
#endif /* HAVE_SQLITE */

bool Database::addToGroup(const KeyId &kid, const Group &group) {
  dcaf_log(DCAF_LOG_DEBUG, "add %s to group %s\n", kid.c_str(), group.c_str());

  groups.insert(std::make_pair(kid,group));
  return true;
}

bool Database::addToRules(const Audience &aud, const Rule &rule) {
  dcaf_log(DCAF_LOG_DEBUG, "add rule for %s: allow %u on %s for %s\n",
           aud.c_str(), rule.permissions, rule.resource.c_str(), rule.group.c_str());

  rules.insert(std::make_pair(aud,rule));
  return true;
}

const map<string, string> Database::fields{
  pair{ Database::Keys::table, Database::Keys::field_def }
};

bool Database::Keys::add(const string &id, unsigned int key_type,
                         const string &data, unsigned long expiry) {
  std::ostringstream str;
  str << std::quoted(id) << ','
      << std::quoted(data) << ','
      << key_type << ','
      << expiry;
  return db.insert_into_table(table, "kid, data, type, expires", str.str());
}

bool Database::Keys::get_by_id(const string &id) {
  std::ostringstream where;
  where << "where kid=" << std::quoted(id);
  return db.select_from_table(table, fields, where.str());
}

Database::Database(const string &dbname, bool memonly)
  : keys(*this), mem(memonly || !sqlite3) {
  open(dbname, "");
}

Database::Database(const string &dbname, const string &vfs, bool memonly)
  : keys(*this), mem(memonly || !sqlite3)  {
  open(dbname, vfs);
}

Database::~Database(void) {
  delete db;
}

bool Database::create_table(const string &table) {
  if (mem) {
    /* TODO: create table for in-memory-layout */
    (void)table;
  }
#ifdef HAVE_SQLITE
  else {
    string sql{"create table if not exists " + table + " (" + fields.find(table)->second + ")"};
    int code;
    sqlite3_stmt *stmt;
    code = sqlite3_prepare_v2(*db, sql.c_str(), sql.size() + 1, &stmt, nullptr);
    if (code == SQLITE_OK) {
      code = sqlite3_step(stmt);
      if (code != SQLITE_DONE) {
        std::cerr << "step returned " << status << std::endl;
      } else {
        code = SQLITE_OK;
      }
    }
    sqlite3_finalize(stmt);
    return (status = code) == SQLITE_OK;
  }
#endif /* HAVE_SQLITE */
  return false;
}

bool Database::insert_into_table(const string &table,
                                 const string &flds,
                                 const string &values) {
  if (mem) {
    /* TODO: create table for in-memory-layout */
    (void)table;
    (void)flds;
    (void)values;
  }
#ifdef HAVE_SQLITE
  else {
    string sql{"insert into " + table + " (" + flds +") values (" + values +");"};
    int code;
    sqlite3_stmt *stmt;
    std::cout << sql << std::endl;
    code = sqlite3_prepare_v2(*db, sql.c_str(), sql.size() + 1, &stmt, nullptr);
    if (code == SQLITE_OK) {
      code = sqlite3_step(stmt);
      if (code != SQLITE_DONE) {
        std::cerr << "step returned " << status << std::endl;
      } else {
        std::cerr << "insert k " << status << std::endl;
        code = SQLITE_OK;
      }
    }
    sqlite3_finalize(stmt);
    return (status = code) == SQLITE_OK;
  }
#endif /* HAVE_SQLITE */
  return false;
}

bool Database::select_from_table(const string &table, const string &flds,
                                 const string &where) {
  if (mem) {
    /* TODO: create table for in-memory-layout */
    (void)table;
    (void)flds;
    (void)where;
  }
#ifdef HAVE_SQLITE
  else {
    string sql{"select " + flds + " from " + table + " " + where + ";"};
    int code;
    sqlite3_stmt *stmt;
    std::cout << sql << std::endl;
    code = sqlite3_prepare_v2(*db, sql.c_str(), sql.size() + 1, &stmt, nullptr);
    if (code == SQLITE_OK) {
      const int max_cols = sqlite3_column_count(stmt);
      while ((code = sqlite3_step(stmt)) == SQLITE_ROW) {
        for (int col = 0; col < max_cols; ++col) {
          sqlite3_value *value = sqlite3_column_value(stmt, col);
          if (value) {
            std::cout << "have a value of type " << sqlite3_column_type(stmt, col) << " for column " << col << std::endl;
          }
        }
      }
      if (code != SQLITE_DONE) {
        std::cerr << "step returned " << status << std::endl;
      } else {
        code = SQLITE_OK;
      }
    }
    sqlite3_finalize(stmt);
    return (status = code) == SQLITE_OK;
  }
#endif /* HAVE_SQLITE */
  return false;
}

bool Database::open(const string &dbname, const string &vfs) {
  if (mem) {
    /* TODO: create table for in-memory-layout */
    (void)dbname;
    (void)vfs;
  }
#ifdef HAVE_SQLITE
  else {
    db = new SQLite{dbname, vfs};
    if (db) {
      /* check for our tables */
      return create_table(Keys::table) && keys.add("dcaf", 1, "secretPSK", 1233456);
    }
  }
#endif /* HAVE_SQLITE */
  return false;
}

Database::operator bool(void) const {
  return db && *db;
}

const char *Database::errmsg(void) const {
  return db ? db->errmsg() : nullptr;
}

} /* namespace am */
// int main(void) {
//   am::Database db{"test.db"};
//   if (!db) {
//     std::cerr << "uh, kaputt: " << db.errmsg() << std::endl;
//   } else {
//     db.keys.get_by_id("dcaf");
//   }
// }
