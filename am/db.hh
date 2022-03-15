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

#include <algorithm>
#include <string>
#include <map>

#include "rule.hh"

namespace am {

class Database {
public:
  Database(const std::string &dbname, bool memonly = false);
  Database(const std::string &dbname, const std::string &vfs, bool memonly = false);
  Database(const Database &) = delete;
  Database(const Database &&) = delete;
  ~Database(void);

  Database &operator=(const Database &) = delete;
  Database &operator=(const Database &&) = delete;
  
  operator bool(void) const;
  const char *errmsg(void) const;

  /**
   * Adds the combination of @p key and @p group to the internal
   * storage.
   *
   * @param key   The dcaf_key_t to store.
   * @param group The group to which @p key is associated.
   * @return      @c true if (key, group) was successfully
   *              stored.
   *
   * TODO: hide dcaf_key_t implementation
   */
  bool addToGroup(const KeyId &kid, const Group &group);

  /**
   * Retrieves all groups for the given @p key and adds them to
   * the output iterator @p out.
   */
  template <class OutputIterator>
  void findGroups(const KeyId &kid, OutputIterator out) const {
    std::transform(groups.lower_bound(kid), groups.upper_bound(kid),
                   out, [](const auto &p) { return p.second; });
  }

  /**
   * Adds the given @p aud and @p rule to the rule storage.
   *
   * @param aud   The audience associated with the @p rule.
   * @param rule  The rule associated with @p aud.
   * @return      @c true if (aud, rule) was successfully
   *              stored.
   */
  bool addToRules(const Audience &aud, const Rule &rule);

  /**
   * Retrieves all rules for the given @p aud and adds them to
   * the output iterator @p out.
   */
  template <class OutIter>
  void findRules(const Audience &aud, OutIter out) const {
    std::transform(rules.lower_bound(aud), rules.upper_bound(aud),
                   out, [](const auto &p) { return p.second; });
  }

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

  Groups groups;
  Rules rules;
};

} /* namespace am */

#endif /* _DB_HH */
