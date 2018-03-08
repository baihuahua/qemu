/*
 * Copyright 2017, Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <inttypes.h>
#include <limits.h>

#include "ccan/list/list.h"

#include <scsi/scsi.h>

#include "libtcmu_common.h"
#include "libtcmu_priv.h"
#include "target.h"
#include "alua.h"

static void tcmu_release_tgt_ports(struct alua_grp *group)
{
	struct tgt_port *port, *port_next;

	list_for_each_safe(&group->tgt_ports, port, port_next, entry) {
		list_del(&port->entry);
		tcmu_free_tgt_port(port);
	}
}

static void tcmu_free_alua_grp(struct alua_grp *group)
{
	tcmu_release_tgt_ports(group);

	if (group->name)
		free(group->name);
	free(group);
}
void tcmu_release_alua_grps(struct list_head *group_list)
{
	struct alua_grp *group, *group_next;

	list_for_each_safe(group_list, group, group_next, entry) {
		list_del(&group->entry);
		tcmu_free_alua_grp(group);
	}
}

/*
 * tcmu does not pass up the target port that the command was
 * received on, so if a LUN is exported through multiple ports
 * in different ALUA target port group we do not know which group
 * to use.
 *
 * For now we support one target port group that contains all
 * enabled ports, or for HA configs one local target port group with
 * enabled ports and N remote port groups which are marked disabled
 * on the the local node.
 */
struct tgt_port *tcmu_get_enabled_port(struct list_head *group_list)
{
	struct alua_grp *group;
	struct tgt_port *port;

	list_for_each(group_list, group, entry) {
		list_for_each(&group->tgt_ports, port, entry) {
			if (port->enabled)
				return port;
		}
	}

	return NULL;
}

int tcmu_emulate_report_tgt_port_grps(struct tcmu_device *dev,
				      struct list_head *group_list,
				      struct tcmulib_cmd *cmd)
{
	struct alua_grp *group;
	struct tgt_port *port;
	int ext_hdr = cmd->cdb[1] & 0x20;
	uint32_t off = 4, ret_data_len = 0, ret32;
	uint32_t alloc_len = tcmu_get_xfer_length(cmd->cdb);
	uint8_t *buf;

	if (!tcmu_get_enabled_port(group_list))
		return TCMU_NOT_HANDLED;

	if (alloc_len < 4)
		return tcmu_set_sense_data(cmd->sense_buf, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB, NULL);

	buf = calloc(1, alloc_len);
	if (!buf)
		return tcmu_set_sense_data(cmd->sense_buf, HARDWARE_ERROR,
					   ASC_INTERNAL_TARGET_FAILURE, NULL);

	if (ext_hdr && alloc_len > 5) {
		buf[4] = 0x10;
		/*
		 * assume all groups will have the same value for now.
		 */
		group = list_first_entry(group_list, struct alua_grp,
					 entry);
		if (group)
			buf[5] = group->implicit_trans_secs;
		off = 8;
	}

	list_for_each(group_list, group, entry) {
		int next_off = off + 8 + (group->num_tgt_ports * 4);

		if (next_off > alloc_len) {
			ret_data_len += next_off;
			continue;
		}

		if (group->pref)
			buf[off] = 0x80;

		buf[off++] |= group->state;
		buf[off++] |= group->supported_states;
		buf[off++] = (group->id >> 8) & 0xff;
		buf[off++] = group->id & 0xff;
		/* reserved */
		off++;
		buf[off++] = group->status;
		/* vendor specific */
		off++;
		buf[off++] = group->num_tgt_ports;

		ret_data_len += 8;

		list_for_each(&group->tgt_ports, port, entry) {
			/* reserved */
			off += 2;
			buf[off++] = (port->rel_port_id >> 8) & 0xff;
			buf[off++] = port->rel_port_id & 0xff;

			ret_data_len += 4;
		}

	}
	ret32 = htobe32(ret_data_len);
	memcpy(&buf[0], &ret32, 4);

	tcmu_memcpy_into_iovec(cmd->iovec, cmd->iov_cnt, buf, alloc_len);
	free(buf);
	return SAM_STAT_GOOD;
}
