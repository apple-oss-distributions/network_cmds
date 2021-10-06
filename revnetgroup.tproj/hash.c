/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/* $OpenBSD: hash.c,v 1.1 1997/04/15 22:06:11 maja Exp $ */
/*
 * Copyright (c) 1995
 *	Bill Paul <wpaul@ctr.columbia.edu>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: hash.c,v 1.4 1997/02/22 14:22:01 peter Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "hash.h"

#ifndef lint
static const char rcsid[] = "$OpenBSD: hash.c,v 1.1 1997/04/15 22:06:11 maja Exp $";
#endif

/*
 * This hash function is stolen directly from the
 * Berkeley DB package. It already exists inside libc, but
 * it's declared static which prevents us from calling it
 * from here.
 */
/*
 * OZ's original sdbm hash
 */
u_int32_t
hash(keyarg, len)
	const void *keyarg;
	register size_t len;
{
	register const u_char *key;
	register size_t loop;
	register u_int32_t h;

#define HASHC   h = *key++ + 65599 * h

	h = 0;
	key = keyarg;
	if (len > 0) {
		loop = (len + 8 - 1) >> 3;

		switch (len & (8 - 1)) {
		case 0:
			do {
				HASHC;
				/* FALLTHROUGH */
		case 7:
				HASHC;
				/* FALLTHROUGH */
		case 6:
				HASHC;
				/* FALLTHROUGH */
		case 5:
				HASHC;
				/* FALLTHROUGH */
		case 4:
				HASHC;
				/* FALLTHROUGH */
		case 3:
				HASHC;
				/* FALLTHROUGH */
		case 2:
				HASHC;
				/* FALLTHROUGH */
		case 1:
				HASHC;
			} while (--loop);
		}
	}
	return (h);
}

/*
 * Generate a hash value for a given key (character string).
 * We mask off all but the lower 8 bits since our table array
 * can only hold 256 elements.
 */
u_int32_t hashkey(key)
	char *key;
{

	if (key == NULL)
		return (-1);
	return(hash((void *)key, strlen(key)) & HASH_MASK);
}

/* Find an entry in the hash table (may be hanging off a linked list). */
char *lookup(table, key)
	struct group_entry *table[];
	char *key;
{
	struct group_entry *cur;

	cur = table[hashkey(key)];

	while (cur) {
		if (!strcmp(cur->key, key))
			return(cur->data);
		cur = cur->next;
	}

	return(NULL);
}

/*
 * Store an entry in the main netgroup hash table. Here's how this
 * works: the table can only be so big when we initialize it (TABLESIZE)
 * but the number of netgroups in the /etc/netgroup file could easily be
 * much larger than the table. Since our hash values are adjusted to
 * never be greater than TABLESIZE too, this means it won't be long before
 * we find ourselves with two keys that hash to the same value.
 *
 * One way to deal with this is to malloc(2) a second table and start
 * doing indirection, but this is a pain in the butt and it's not worth
 * going to all that trouble for a dinky little program like this. Instead,
 * we turn each table entry into a linked list and simply link keys
 * with the same hash value together at the same index location within
 * the table.
 *
 * That's a lot of comment for such a small piece of code, isn't it.
 */
void store (table, key, data)
	struct group_entry *table[];
	char *key, *data;
{
	struct group_entry *new;
	u_int32_t i;

	i = hashkey(key);

	new = (struct group_entry *)malloc(sizeof(struct group_entry));
	new->key = strdup(key);
	new->data = strdup(data);
	new->next = table[i];
	table[i] = new;

	return;
}

/*
 * Store a group member entry and/or update its grouplist. This is
 * a bit more complicated than the previous function since we have to
 * maintain not only the hash table of group members, each group member
 * structure also has a linked list of groups hung off it. If handed
 * a member name that we haven't encountered before, we have to do
 * two things: add that member to the table (possibly hanging them
 * off the end of a linked list, as above), and add a group name to
 * the member's grouplist list. If we're handed a name that already has
 * an entry in the table, then we just have to do one thing, which is
 * to update its grouplist.
 */
void mstore (table, key, data, domain)
	struct member_entry *table[];
	char *key, *data, *domain;
{
	struct member_entry *cur, *new;
	struct grouplist *tmp,*p;
	u_int32_t i;

	i = hashkey(key);
	cur = table[i];

	tmp = (struct grouplist *)malloc(sizeof(struct grouplist));
	tmp->groupname = strdup(data);
	tmp->next = NULL;

	/* Check if all we have to do is insert a new groupname. */
	while (cur) {
		if (!strcmp(cur->key, key) && !strcmp(cur->domain,domain)) {
		  	p = cur->groups;
			while(p) {
				if (!strcmp(p->groupname,data))
					return;
				p = p->next;
			}
			tmp->next = cur->groups;
			cur->groups = tmp;
			return;
		}
		cur = cur->next;
	}

	/* Didn't find a match -- add the whole mess to the table. */
	new = (struct member_entry *)malloc(sizeof(struct member_entry));
	new->key = strdup(key);
	new->domain = strdup(domain);
	new->groups = tmp;
	new->next = table[i];
	table[i] = new;

	return;
}
