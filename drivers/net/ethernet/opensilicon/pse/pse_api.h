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

#ifndef _PSE_API_H_
#define _PSE_API_H_

/* flow control */
int fc_th_write(u16 set, u16 release);
int fc_th_read(u16 *set, u16 *release);
int fc_th_drop_write(u16 set, u16 release);
int fc_th_drop_read(u16 *set, u16 *release);
int fc_th_all_drop_write(u16 set, u16 release);
int fc_th_all_drop_read(u16 *set, u16 *release);
int fc_th_input_write(u8 port, u16 set, u16 release);
int fc_th_input_read(u8 port, u16 *set, u16 *release);

/* police */
int police_port_en_write(u8 port, bool enable);
bool police_port_en_read(u8 port);
int police_psudo_rand_generator_write(bool enable);
bool police_psudo_rand_generator_read(void);
int police_global_min_th_write(u16 th);
u16 police_global_min_th_read(void);

int police_dst_port_write(u8 port, u16 queue_en, u16 max, u16 min, u16 probability, u16 weight, u16 min_oq);
int police_dst_port_read(u8 port, u16 *queue_en, u16 *inverse, u16 *max, u16 *min, u16 *probability, u16 *weight, u16 *min_oq);

/* shape */
int get_bucket_size(u8 port, u8 base, u8 bw);
int shape_port_write(u8 port, u8 base, u8 bw, u8 bucket_size);
int shape_port_read(u8 port, u8 *base, u8 *bw, u8 *bucket_size);
int shape_queue_write(u8 port, u8 queue, u8 base, u8 bw, u8 bucket_size);
int shape_queue_read(u8 port, u8 queue, u8 *base, u8 *bw, u8 *bucket_size);
int shape_bucket_size_write(u8 port, u8 size);
int shape_bucket_size_read(u8 port, u8 *size);
int shape_two_bucket_size_write(u8 size);
int shape_two_bucket_size_read(u8 *size);

/* traffic class */
int tc_port(u8 port, u8 tc);
int tc_to_ring(u8 port, u8 tc, u8 ring);
int tc_cfg_ethertype(u8 port, bool enable);
int tc_cfg_vlan(u8 port, bool enable);
int tc_cfg_dscp(u8 port, bool enable);
int tc_cfg_udp(u8 port, bool enable);
int tc_cfg_tcp(u8 port, bool enable);
int tc_cfg_dmac(u8 port, bool enable);
int tc_cfg_regen_user_pri(u8 port, bool enable);

int tc_ethertype(u8 index, u16 type, u8 tc);
int tc_ethertype_read(u8 index, u16 *type, u8 *tc);
int tc_dscp(u8 dscp_index, u8 tc);
int tc_dscp_read(u8 dscp_index, u8 *tc);
int tc_tcp_port(u8 index, u16 start, u16 end, u8 tc);
int tc_tcp_port_read(u8 index, u16 *start, u16 *end, u8 *tc);
int tc_udp_port(u8 index, u16 start, u16 end, u8 tc);
int tc_udp_port_read(u8 index, u16 *start, u16 *end, u8 *tc);

/* TX schedule */
int tx_sch_mode(u8 port, u8 mode);
int tx_sch_min_bw(u8 port, u8 bw);
int tx_sch_weight(u8 port, u8 tc, u8 weight);
#endif /* _PSE_API_H_ */
