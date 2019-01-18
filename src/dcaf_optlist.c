/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 * -*- */

/* dcaf_optlist.c -- Ordered list of CoAP options
 *
 * Copyright (C) 2010,2011,2015-2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README for terms of
 * use.
 */

#include <stdio.h>
#include <string.h>

#include "dcaf/dcaf.h"
#include "dcaf/dcaf_int.h"
#include "dcaf/dcaf_coap.h"
#include "dcaf/dcaf_optlist.h"
#include "dcaf/dcaf_mem.h"
#include "dcaf/utlist.h"

bool
dcaf_set_option(struct dcaf_context_t *context,
                dcaf_option optnum,
                const dcaf_option_t *option) {
  if (context) {
    switch (optnum) {
    default: return false;
    case DCAF_OPTION_TIMEOUT:
      if (option) {
        context->timeout_ms = option->v.uint;
        return true;
      }
      break;
    }
  }
  return false;
}

#if 0
dcaf_option_t *
dcaf_option_create(unsigned int type, unsigned char *data, size_t datalen) {
  dcaf_option_t *opt;

  opt = dcaf_alloc_type_len(DCAF_OPTION, datalen);
  if (opt) {
    opt->next = NULL;
    opt->key = type;
    opt->size = datalen;
    memcpy(opt->data, data, datalen);
  }

  return opt;
}

void
dcaf_option_delete(dcaf_option_t *option) {
  /* FIXME */
  coap_free(option);
}

void
dcaf_optlist_insert(dcaf_optlist_t *queue, dcaf_option_t *node) {
  dcaf_option_t *el;
  assert(queue);

  if (!node) {
    return;
  }

  LL_FOREACH(*queue, el) {
    if (node->key < el->key) {
      break;
    }
  }

  if (el) {
    LL_PREPEND_ELEM(*queue, el, node);
  } else {
    LL_APPEND(*queue, node);
  }
}

void
dcaf_optlist_remove_key(dcaf_optlist_t *queue, unsigned short key) {
  dcaf_option_t *el, *tmp;

  LL_FOREACH_SAFE(*queue, el, tmp) {
    if (key < el->key) {
      break;
    } else if (key == el->key) {
      LL_DELETE(*queue, el);
      dcaf_option_delete(el);
    }
  }
}

void
dcaf_optlist_delete_all(dcaf_optlist_t *queue) {
  dcaf_option_t *el, *tmp;
 
  LL_FOREACH_SAFE(*queue, el, tmp) {
    dcaf_option_delete(el);
  }
  *queue = NULL;
}

dcaf_option_t *
dcaf_optlist_find_first(dcaf_optlist_t queue, unsigned int key) {
  dcaf_option_t *el;
  assert(queue);

  LL_FOREACH(queue, el) {
    if (el->key == key) {
      return el;
    }
  }

  return NULL;
}

dcaf_option_t *
dcaf_optlist_get_next(dcaf_option_t *node) {
  return node ? node->next : NULL;
}

ssize_t
dcaf_optlist_serialize(dcaf_optlist_t node, coap_pdu_t *pdu) {
  size_t sum = 0;

  while (node) {
    size_t written = coap_add_option(pdu, node->key, node->size, node->data);

    if (written == 0) {
      warn("cannot add option %d: buffer too small\n", node->key);
      return -1;
    }

    sum += written;
    node = dcaf_optlist_get_next(node);
  }

  return sum;
}
#endif
