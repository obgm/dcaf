/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* dcaf_optlist.h -- Ordered list of CoAP options
 *
 * Copyright (C) 2010,2011,2015-2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the DCAF library libdcaf. Please see README for terms of
 * use.
 */

#ifndef _DCAF_OPTLIST_H_
#define _DCAF_OPTLIST_H_


/** Representation of CoAP options. */
typedef struct dcaf_option_t {
  struct dcaf_option_t *next;   /* internal use */
  unsigned int key;             /**< option type */
  size_t size;                  /**< length of data in bytes */

  /**
   * option value
   *
   * As ISO C++ forbids flexible arrays at least one byte needs to be
   * reserved.
   */
  unsigned char data[1];
} dcaf_option_t;

/** Sorted list of CoAP options. */
typedef dcaf_option_t *dcaf_optlist_t;

/**
 * Allocates storage for a new option that is initialized with the
 * specified values. The option must be released using
 * dcaf_option_delete(). The @p data passed to this function will be
 * copied.
 *
 * @param type The option type.
 * @param data The data to be used for this option.
 * @param datalen The actual length of @p data in bytes.
 * @return A new option object or @c NULL on error.
 */
dcaf_option_t *dcaf_option_create(unsigned int type, unsigned char *data, size_t datalen);

/**
 * Releases the storage that has been allocated for @p option.
 */
void dcaf_option_delete(dcaf_option_t *option);


/**
 * Adds @p node to given @p queue.
 */
void dcaf_optlist_insert(dcaf_optlist_t *queue, dcaf_option_t *node);

/**
 * Removes all elements with given @p key from @p queue.  For any
 * removed element, this function calls dcaf_option_delete()
 * automatically.
 */
void dcaf_optlist_remove_key(dcaf_optlist_t *queue, unsigned short key);

/**
 * Removes all nodes from given @p node and calls dcaf_option_delete()
 * for each node.
 *
 * @param queue The list to free.
 */
void dcaf_optlist_delete_all(dcaf_optlist_t *queue);

/**
 * Retrieves the first element with given @p key from @p queue.
 *
 * @param queue A pointer to the option list to search.
 * @param key   The option key to look for.
 * @return A pointer to the first element in @p queue that matches the
 *         given @p key, or @c NULL if none was found.
 */
dcaf_option_t *dcaf_optlist_find_first(dcaf_optlist_t queue, unsigned int key);

/**
 * Returns the successor of @p node in list.
 *
 * @param node The element to start with.
 * @return A pointer to the element that follows @p node, 
 *         or @c NULL if @p node was the last element.
 */
dcaf_option_t *dcaf_optlist_get_next(dcaf_option_t *node);

struct coap_pdu_t;
/**
 * Writes the options from @p queue into the specified @p pdu.  This
 * function returns the number of bytes that have been written into
 * the PDU's buffer or -1 in case of an error. An error may occur when
 * the PDU's data buffer is too small.
 *
 * @param queue The option list to output.
 * @param pdu   The CoAP PDU where the options are written.
 * @return The number of bytes written on success, or -1 otherwise.
 */
ssize_t dcaf_optlist_serialize(dcaf_optlist_t queue, struct coap_pdu_t *pdu);

#endif /* _DCAF_OPTLIST_H_ */
