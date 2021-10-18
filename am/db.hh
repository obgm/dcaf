/*
 * db.hh -- Database handling for DCAF authorization manager
 *
 * Copyright (C) 2018-2021 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef _DB_HH
#define _DB_HH 1

#include <string>
#include <map>

namespace am {

class Database {
public:
  Database(const std::string &dbname, bool memonly = false);
  Database(const std::string &dbname, const std::string &vfs, bool memonly = false);
  Database(const Database &) = delete;
  Database(const Database &&);
  ~Database(void);

  Database &operator=(const Database &) = delete;
  Database &operator=(const Database &&) = delete;
  
  operator bool(void) const;
  const char *errmsg(void) const;

  class Keys {
    Database &db;
  public:
    constexpr static const char *table = "Keys";
    constexpr static const char *field_def =
      "kid BLOB, data BLOB, type INTEGER, expires INTEGER";
    constexpr static const char *fields = "kid, data, type, expires";

    Keys(Database &db_) : db(db_) {}
    bool add(const std::string &id, unsigned int key_type,
             const std::string &data, unsigned long expiry);
    bool get_by_id(const std::string &id);
  } keys;
private:
  const bool mem;               //< true if always in memory
  class Implementation;
  class SQLite;
  /**
   * The database object is either an in-memory structure or an sqlite
   * handle, depending on the actual build configuration.
   */
  Implementation *db;
  int status;
  
  static const std::map<std::string, std::string> fields;

  bool open(const std::string &dbname, const std::string &vfs);
  bool create_table(const std::string &table);
  bool insert_into_table(const std::string &table, const std::string &fields,
                         const std::string &values);
  bool select_from_table(const std::string &table, const std::string &fields,
                         const std::string &where);
};

} /* namespace am */

#endif /* _DB_HH */
