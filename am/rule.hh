/*
 * rule.hh -- Authorization rule representation for DCAF AM
 *
 * Copyright (C) 2018-2021 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README
 * for terms of use.
 */

#ifndef AM_RULE_HH
#define AM_RULE_HH 1
#include <functional>
#include <map>
#include <string>

#include <cstring>

#include "dcaf/dcaf_int.h"

template <>
struct std::less <dcaf_key_t> {
  constexpr bool ls(const uint8_t *as, size_t alen,
                    const uint8_t *bs, size_t blen) const {
    return (alen < blen) || (alen == blen && memcmp(as, bs, alen) < 0);
  }
  constexpr bool operator()(const dcaf_key_t& lhs,
                            const dcaf_key_t& rhs) const {
    return (lhs.type < rhs.type) || (lhs.type == rhs.type &&
                                     ls(lhs.kid, rhs.kid_length,
                                        lhs.kid, rhs.kid_length));
  }
};

namespace am {

/*
 * Subjects are identified by keys. Each subject
 * is in zero or more groups.
 */
using Group = std::string;
using Groups = std::multimap<dcaf_key_t, Group>;

/* A resource is identified by a relative path. */
using Resource = std::string;
/**
 * A Rule consists of a resource description
 * and a set of permissions.
 */
struct Rule {
  Resource resource;
  Group group;
  uint32_t permissions;
};

/*
 * Zero or more rules are in effect for an
 * Audience and Group.
 */
using Audience = std::string;
using Rules = std::multimap<Audience, Rule>;

} /* namespace am */

#endif /* AM_RULE_HH */
