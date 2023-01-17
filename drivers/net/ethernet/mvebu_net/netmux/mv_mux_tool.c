/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File in accordance with the terms and conditions of the General
Public License Version 2, June 1991 (the "GPL License"), a copy of which is
available along with the File in the license.txt file or by writing to the Free
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 or
on the worldwide web at http://www.gnu.org/licenses/gpl.txt.

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY
DISCLAIMED.  The GPL License provides additional details about this warranty
disclaimer.

*******************************************************************************/

#include "mv_mux_tool.h"
#include <linux/ethtool.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
static int __ethtool_get_settings(struct net_device *dev, void __user *useraddr)
{
	struct ethtool_cmd cmd = { ETHTOOL_GSET };
	int err;

	if (!dev->ethtool_ops->get_settings)
		return -EOPNOTSUPP;

	err = dev->ethtool_ops->get_settings(dev, &cmd);
	if (err < 0)
		return err;

	if (copy_to_user(useraddr, &cmd, sizeof(cmd)))
		return -EFAULT;
	return 0;
}
#endif

/******************************************************************************
*mv_mux_tool_get_settings
*Description:
*	ethtool	get standard port settings
*INPUT:
*	netdev	Network device structure pointer
*OUTPUT
*	cmd	command (settings)
*RETURN:
*	0 for success
*
*******************************************************************************/
int mv_mux_tool_get_settings(struct net_device *netdev, struct ethtool_cmd *cmd)
{
	struct mux_netdev *pmux_priv = MV_MUX_PRIV(netdev);
	struct net_device *root = mux_eth_shadow[pmux_priv->port].root;

	if (!root)
		return -ENETUNREACH;

	return __ethtool_get_settings(root, cmd);
}
/******************************************************************************
*mv_mux_tool_get_drvinfo
*Description:
*	ethtool get driver information
*INPUT:
*	netdev	Network device structure pointer
*	info	driver information
*OUTPUT
*	info	driver information
*RETURN:
*	None
*
*******************************************************************************/
void mv_mux_tool_get_drvinfo(struct net_device *netdev, struct ethtool_drvinfo *info)
{
	struct mux_netdev *pmux_priv = MV_MUX_PRIV(netdev);
	struct net_device *root = mux_eth_shadow[pmux_priv->port].root;

	if (!root || !root->ethtool_ops || !root->ethtool_ops->get_drvinfo)
		return;


	root->ethtool_ops->get_drvinfo(root, info);
}

/******************************************************************************
*mv_mux_tool_get_coalesce
*Description:
*	ethtool get RX/TX coalesce parameters
*INPUT:
*	netdev	Network device structure pointer
*OUTPUT
*	cmd	Coalesce parameters
*RETURN:
*	0 on success
*
*******************************************************************************/
int mv_mux_tool_get_coalesce(struct net_device *netdev, struct ethtool_coalesce *cmd)
{
	struct mux_netdev *pmux_priv = MV_MUX_PRIV(netdev);
	struct net_device *root = mux_eth_shadow[pmux_priv->port].root;

	if (!root || !root->ethtool_ops || !root->ethtool_ops->get_coalesce)
		return -ENETUNREACH;

	return root->ethtool_ops->get_coalesce(root, cmd);

}
/******************************************************************************
*mv_mux_tool_get_pauseparam
*Description:
*	ethtool get pause parameters
*INPUT:
*	netdev	Network device structure pointer
*OUTPUT
*	pause	Pause paranmeters
*RETURN:
*	None
*
*******************************************************************************/
void mv_mux_tool_get_pauseparam(struct net_device *netdev, struct ethtool_pauseparam *pause)
{
	struct mux_netdev *pmux_priv = MV_MUX_PRIV(netdev);
	struct net_device *root = mux_eth_shadow[pmux_priv->port].root;

	if (!root || !root->ethtool_ops || !root->ethtool_ops->get_pauseparam)
		return;

	root->ethtool_ops->get_pauseparam(root, pause);
}


/******************************************************************************
* mv_mux_tool_nway_reset
* Description:
*	ethtool restart auto negotiation
* INPUT:
*	netdev	Network device structure pointer
* OUTPUT
*	None
* RETURN:
*	0 on success
*
*******************************************************************************/
#ifdef CONFIG_MV_INCLUDE_SWITCH
int mv_mux_tool_nway_reset(struct net_device *mux_dev)
{
	struct mux_netdev *pdev_priv;

	pdev_priv = MV_MUX_PRIV(mux_dev);
	/* restart group autoneg */
	if (mv_switch_group_restart_autoneg(pdev_priv->idx))
		return -EINVAL;

	return 0;
}
#endif

/******************************************************************************
* mv_mux_tool_get_link
* Description:
*	ethtool get link status
* INPUT:
*	netdev	Network device structure pointer
* OUTPUT
*	None
* RETURN:
*	0 if link is down, 1 if link is up
*
*******************************************************************************/
#ifdef CONFIG_MV_INCLUDE_SWITCH
u32 mv_mux_tool_get_link(struct net_device *mux_dev)
{
	struct mux_netdev *pdev_priv;

	pdev_priv = MV_MUX_PRIV(mux_dev);

	return mv_switch_link_status_get(pdev_priv->idx);
}
#endif


const struct ethtool_ops mv_mux_tool_ops = {
	.get_settings	= mv_mux_tool_get_settings,
	.get_pauseparam	= mv_mux_tool_get_pauseparam,
	.get_coalesce	= mv_mux_tool_get_coalesce,
	.get_link	= ethtool_op_get_link,
	.get_drvinfo	= mv_mux_tool_get_drvinfo,
#ifdef CONFIG_MV_INCLUDE_SWITCH
	.nway_reset	= mv_mux_tool_nway_reset,
	.get_link	= mv_mux_tool_get_link,
#endif
};
