/*
 * LibHTP (http://www.libhtp.org)
 * Copyright 2009,2010 Ivan Ristic <ivanr@webkreator.com>
 *
 * LibHTP is an open source product, released under terms of the General Public Licence
 * version 2 (GPLv2). Please refer to the file LICENSE, which contains the complete text
 * of the license.
 *
 * In addition, there is a special exception that allows LibHTP to be freely
 * used with any OSI-approved open source licence. Please refer to the file
 * LIBHTP_LICENSING_EXCEPTION for the full text of the exception.
 *
 */

#include <stdlib.h>
#include <stdio.h>

#include "dslib.h"


// -- Queue List --

/**
 * Add element to list.
 *
 * @param list
 * @param element
 * @return 1 on success, -1 on error (memory allocation failure)
 */
static int list_linked_push(list_t *_q, void *element) {
    list_linked_t *q = (list_linked_t *) _q;
    list_linked_element_t *qe = calloc(1, sizeof (list_linked_element_t));
    if (qe == NULL) return -1;

    // Rememeber the element
    qe->data = element;

    // If the queue is empty, make this element first
    if (!q->first) {
        q->first = qe;
    }

    if (q->last) {
        q->last->next = qe;
    }

    q->last = qe;

    return 1;
}

/**
 * Remove one element from the beginning of the list.
 *
 * @param list
 * @return a pointer to the removed element, or NULL if the list is empty.
 */
static void *list_linked_pop(list_t *_q) {
    list_linked_t *q = (list_linked_t *) _q;
    void *r = NULL;

    if (!q->first) {
        return NULL;
    }

    list_linked_element_t *qe = q->first;
    q->first = qe->next;
    r = qe->data;

    if (!q->first) {
        q->last = NULL;
    }

    free(qe);

    return r;
}

/**
 * Is the list empty?
 *
 * @param list
 * @return 1 if the list is empty, 0 if it is not
 */
static int list_linked_empty(list_t *_q) {
    list_linked_t *q = (list_linked_t *) _q;

    if (!q->first) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * Destroy list. This function will not destroy any of the
 * data stored in it. You'll have to do that manually beforehand.
 *
 * @param l
 */
void list_linked_destroy(list_linked_t *l) {
    // Free the list structures
    list_linked_element_t *temp = l->first;
    list_linked_element_t *prev = NULL;
    while (temp != NULL) {
        free(temp->data);
        prev = temp;
        temp = temp->next;
        free(prev);
    }

    // Free the list itself
    free(l);
}

/**
 * Create a new linked list.
 *
 * @return a pointer to the newly creted list (list_t), or NULL on memory allocation failure
 */
list_t *list_linked_create(void) {
    list_linked_t *q = calloc(1, sizeof (list_linked_t));
    if (q == NULL) return NULL;

    q->push = list_linked_push;
    q->pop = list_linked_pop;
    q->empty = list_linked_empty;
    q->destroy = (void (*)(list_t *))list_linked_destroy;

    return (list_t *) q;
}

// -- Queue Array --

/**
 * Add new element to the end of the list, expanding the list
 * as necessary.
 *
 * @param list
 * @param element
 *
 * @return 1 on success or -1 on failure (memory allocation)
 */
static int list_array_push(list_t *_q, void *element) {
    list_array_t *q = (list_array_t *) _q;

    // Check if we're full
    if (q->current_size >= q->max_size) {
        int new_size = q->max_size * 2;
        void *newblock = NULL;
        
        if (q->first == 0) {
            // The simple case of expansion is when the first
            // element in the list resides in the first slot. In
            // that case we just add some new space to the end,
            // adjust the max_size and that's that.
            newblock = realloc(q->elements, new_size * sizeof (void *));
            if (newblock == NULL) return -1;
        } else {
            // When the first element is not in the first
            // memory slot, we need to rearrange the order
            // of the elements in order to expand the storage area.
            newblock = malloc(new_size * sizeof (void *));
            if (newblock == NULL) return -1;

            // Copy the beginning of the list to the beginning of the new memory block
            memcpy(newblock, (char *)q->elements + q->first * sizeof (void *), (q->max_size - q->first) * sizeof (void *));
            // Append the second part of the list to the end
            memcpy((char *)newblock + (q->max_size - q->first) * sizeof (void *), q->elements, q->first * sizeof (void *));
            
            free(q->elements);
        }
        
        q->first = 0;
        q->last = q->current_size;
        q->max_size = new_size;
        q->elements = newblock;
    }

    q->elements[q->last] = element;
    q->current_size++;
    
    q->last++;
    if (q->last == q->max_size) {
        q->last = 0;
    }

    return 1;
}

/**
 * Remove one element from the beginning of the list.
 *
 * @param list
 * @return the removed element, or NULL if the list is empty
 */
static void *list_array_pop(list_t *_q) {
    list_array_t *q = (list_array_t *) _q;
    void *r = NULL;

    if (q->current_size == 0) {
        return NULL;
    }

    r = q->elements[q->first];
    q->first++;
    if (q->first == q->max_size) {
        q->first = 0;
    }

    q->current_size--;

    return r;
}

/**
 * Returns the size of the list.
 *
 * @param list
 */
static size_t list_array_size(list_t *_l) {
    return ((list_array_t *) _l)->current_size;
}

/**
 * Return the element at the given index.
 *
 * @param list
 * @param index
 * @return the desired element, or NULL if the list is too small, or
 *         if the element at that position carries a NULL
 */
static void *list_array_get(list_t *_l, size_t idx) {
    list_array_t *l = (list_array_t *) _l;
    void *r = NULL;

    if (idx + 1 > l->current_size) return NULL;

    size_t i = l->first;
    r = l->elements[l->first];

    while (idx--) {
        if (++i == l->max_size) {
            i = 0;
        }

        r = l->elements[i];
    }

    return r;
}

/**
 * Replace the element at the given index with the provided element.
 *
 * @param list
 * @param index
 * @param element
 *
 * @return 1 if the element was replaced, or 0 if the list is too small
 */
static int list_array_replace(list_t *_l, size_t idx, void *element) {
    list_array_t *l = (list_array_t *) _l;    

    if (idx + 1 > l->current_size) return 0;

    size_t i = l->first;

    while (idx--) {
        if (++i == l->max_size) {
            i = 0;
        }
    }

    l->elements[i] = element;

    return 1;
}

/**
 * Reset the list iterator.
 *
 * @param l
 */
void list_array_iterator_reset(list_array_t *l) {
    l->iterator_index = 0;
}

/**
 * Advance to the next list value.
 *
 * @param l
 * @return the next list value, or NULL if there aren't more elements
 *         left to iterate over or if the element itself is NULL
 */
void *list_array_iterator_next(list_array_t *l) {
    void *r = NULL;

    if (l->iterator_index < l->current_size) {
        r = list_get(l, l->iterator_index);
        l->iterator_index++;
    }

    return r;
}

/**
 * Free the memory occupied by this list. This function assumes
 * the data elements were freed beforehand.
 *
 * @param l
 */
void list_array_destroy(list_array_t *l) {
    free(l->elements);
    free(l);
}

/**
 * Create new array-based list.
 *
 * @param size
 * @return newly allocated list (list_t)
 */
list_t *list_array_create(size_t size) {
    // Allocate the list structure
    list_array_t *q = calloc(1, sizeof (list_array_t));
    if (q == NULL) return NULL;

    // Allocate the initial batch of elements
    q->elements = malloc(size * sizeof (void *));
    if (q->elements == NULL) {
        free(q);
        return NULL;
    }

    // Initialise structure
    q->first = 0;
    q->last = 0;
    q->max_size = size;
    q->push = list_array_push;
    q->pop = list_array_pop;
    q->get = list_array_get;
    q->replace = list_array_replace;
    q->size = list_array_size;
    q->iterator_reset = (void (*)(list_t *))list_array_iterator_reset;
    q->iterator_next = (void *(*)(list_t *))list_array_iterator_next;
    q->destroy = (void (*)(list_t *))list_array_destroy;

    return (list_t *) q;
}


// -- Table --

/**
 * Create a new table structure.
 *
 * @param size
 * @return newly created table_t
 */
table_t *table_create(size_t size) {
    table_t *t = calloc(1, sizeof (table_t));
    if (t == NULL) return NULL;

    // Use a list behind the scenes
    t->list = list_array_create(size * 2);
    if (t->list == NULL) {
        free(t);
        return NULL;
    }
    
    return t;
}

/**
 * Destroy a table.
 *
 * @param table
 */
void table_destroy(table_t * table) {
    // Free keys only
    int counter = 0;
    void *data = NULL;

    list_iterator_reset(table->list);

    while ((data = list_iterator_next(table->list)) != NULL) {
        // Free key
        if ((counter % 2) == 0) {
            free(data);
        }

        counter++;
    }

    list_destroy(table->list);

    free(table);
}

/**
 * Add a new table element. This function currently makes a copy of
 * the key, which is inefficient.
 *
 * @param table
 * @param key
 * @param element
 */
int table_add(table_t *table, bstr *key, void *element) {
    // Lowercase key
    bstr *lkey = bstr_dup_lower(key);
    if (lkey == NULL) {
        return -1;
    }   

    // Add key
    if (list_add(table->list, lkey) != 1) {
        free(lkey);
        return -1;
    }

    // Add element
    if (list_add(table->list, element) != 1) {
        list_pop(table->list);
        free(lkey);
        return -1;
    }

    return 1;
}

/**
 * @param table
 * @param key
 */
static void *table_get_internal(table_t *table, bstr *key) {
    // Iterate through the list, comparing
    // keys with the parameter, return data if found.
    bstr *ts = NULL;
    list_iterator_reset(table->list);
    while ((ts = list_iterator_next(table->list)) != NULL) {
        void *data = list_iterator_next(table->list);
        if (bstr_cmp(ts, key) == 0) {
            return data;
        }
    }

    return NULL;
}

/**
 * Retrieve the first element in the table with the given
 * key (as a NUL-terminated string).
 *
 * @param table
 * @param cstr
 * @return table element, or NULL if not found
 */
void *table_getc(table_t *table, char *cstr) {
    if (table == NULL||cstr == NULL)
        return NULL;
    // TODO This is very inefficient
    bstr *key = bstr_cstrdup(cstr);
    if (key == NULL)
        return NULL;
    bstr_tolowercase(key);
    void *data = table_get_internal(table, key);
    free(key);
    return data;
}

/**
 * Retrieve the first element in the table with the given key.
 *
 * @param table
 * @param key
 * @return table element, or NULL if not found
 */
void *table_get(table_t *table, bstr *key) {
    if (table == NULL||key == NULL)
        return NULL;
    // TODO This is very inefficient
    bstr *lkey = bstr_dup_lower(key);
    if (lkey == NULL)
        return NULL;
    void *data = table_get_internal(table, lkey);
    free(lkey);
    return data;
}

/**
 * Reset the table iterator.
 *
 * @param table
 */
void table_iterator_reset(table_t *table) {
    list_iterator_reset(table->list);
}

/**
 * Advance to the next table element.
 *
 * @param t
 * @param data
 * @return pointer to the key and the element if there is a next element, NULL otherwise
 */
bstr *table_iterator_next(table_t *t, void **data) {
    bstr *s = list_iterator_next(t->list);
    if (s != NULL) {
        *data = list_iterator_next(t->list);
    }

    return s;
}

/**
 * Returns the size of the table.
 *
 * @param table
 * @return table size
 */
size_t table_size(table_t *table) {
    return list_size(table->list) / 2;
}

/**
 * Remove all elements from the table.
 *
 * @param table
 */
void table_clear(table_t *table) {    
    // TODO Clear table by removing the existing elements
    if (table == NULL)
        return;
    size_t size = list_size(table->list);

    list_destroy(table->list);
    
    // Use a list behind the scenes
    table->list = list_array_create(size == 0 ? 10 : size);
    if (table->list == NULL) {
        free(table);        
    }    
}

#if 0

int main(int argc, char **argv) {
    list_t *q = list_linked_create();

    list_push(q, "1");
    list_push(q, "2");
    list_push(q, "3");
    list_push(q, "4");

    char *s = NULL;
    while ((s = (char *) list_pop(q)) != NULL) {
        printf("Got: %s\n", s);
    }

    free(q);
}
#endif
