/*
 * Author: Open Silicon, Inc.
 * Contact: platform@open-silicon.com
 * This file is part of the Voledia SDK
 *
 * Copyright (c) 2012 Open-Silicon Inc.
 *
 * This file is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License, Version 2, as published by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but AS-IS and WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE, TITLE, or NONINFRINGEMENT. See the GNU
 * General Public License for more details.
 *
 * This file may also be available under a different license from Open-Silicon.
 * Contact Open-Silicon for more information
 */

#ifndef _PSE_MAC_H_
#define _PSE_MAC_H_

struct pse_mac {
	u16 port:3; /* 0:MAC0, 1:MAC1, 2:CPU, 4:MAC2 */
	u16 index:9; /* MAC index. CPU:0~7, MAC port:0~1; Hash index:0~511 */
	u16 priority:3; /* MY MAC priority */
	u16:1;

	u8 mac[6];
};

struct pse_mac_table_data {
	struct pse_mac mac[OPV5XC_MAC_MAX];
};

enum pse_mac_hash_algo {
	PSE_MAC_HASH_DIRECT = 0,
	PSE_MAC_HASH_XOR = 1,
	PSE_MAC_HASH_CRC16 = 2
};

void pse_mac_hash(enum pse_mac_hash_algo);
int pse_mac_write(struct pse_mac *);
int pse_mac_read(struct pse_mac *);
int pse_mac_hash_write_by_lookup(struct pse_mac *ptr);
int pse_mac_hash_read_by_lookup(struct pse_mac *ptr);
int pse_mac_hash_write_by_index(int port, int index);
int pse_mac_hash_read_by_index(int port, int index);

#endif /* _PSE_MAC_H_ */
