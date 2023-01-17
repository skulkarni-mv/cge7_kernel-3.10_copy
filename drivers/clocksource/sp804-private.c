/*
 * linux/driver/clocksource/sp804-private.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <linux/clk.h>
#include <linux/clocksource.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/sched.h>
#include <linux/posix-clock.h>
#include <linux/idr.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/posix-clock.h>
#include <linux/pps_kernel.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/platform_device.h>
#include "timer-sp.h"
#include <linux/list.h>

#define MODULE_NAME "sp804-private-timer"
#define DUAL_TIMER 2
#define MAX_DEVICE_NAME_LEN 32

static int max_sp804_instances = 4;
module_param(max_sp804_instances, int, 4);

static int timer1_pre_scale = 1;
module_param(timer1_pre_scale, int, 1);

static int timer2_pre_scale = 16;
module_param(timer2_pre_scale, int, 16);

static long sp804_get_clock_rate(struct clk *clk)
{
	long rate;
	int err;

	err = clk_prepare(clk);
	if (err) {
		pr_err("sp804: clock failed to prepare: %d\n", err);
		clk_put(clk);
		return err;
	}

	err = clk_enable(clk);
	if (err) {
		pr_err("sp804: clock failed to enable: %d\n", err);
		clk_unprepare(clk);
		clk_put(clk);
		return err;
	}

	rate = clk_get_rate(clk);
	if (rate < 0) {
		pr_err("sp804: clock failed to get rate: %ld\n", rate);
		clk_disable(clk);
		clk_unprepare(clk);
		clk_put(clk);
	}

	return rate;
}

enum timer_status {
	ACTIVE = 0,
	DEACTIVE
};

struct timer_kit {
	struct list_head list;
	int value;
	enum timer_status status;
	u32 required_ticks;
	u32 left_ticks;
	u32 periodic;
	struct k_itimer *kit;
};

struct private_timer {
	struct list_head head[DUAL_TIMER];
	u32 granularity_us[DUAL_TIMER];
	u32 current_count[DUAL_TIMER];
	u32 prev_count[DUAL_TIMER];
	struct irqaction sp804_private_timer_irq;
	void __iomem *private_clkevt_base;
	struct class *sp804_timer_class;
	dev_t sp804_timer_devt;
	long rate[DUAL_TIMER];
	dev_t clk_div[DUAL_TIMER];
	dev_t pre_scale[DUAL_TIMER];
	dev_t devid[DUAL_TIMER];
	int irq;
	int dev_instance;
} private_timer;

static struct private_timer *sp804_private_timer;

static int sp804_timer_create(struct posix_clock *pc, struct k_itimer *kit)
{
	pr_debug("sp804_timer_create DevId:%d\n", pc->cdev.dev);
	pr_debug("Expected SIGNO:%d\n", kit->sigq->info.si_signo);
	pr_debug("Major:%d Minor:%d\n",
		 MAJOR(pc->cdev.dev), MINOR(pc->cdev.dev));
	return 0;
}

static int sp804_timer_delete(struct posix_clock *pc, struct k_itimer *kit)
{
	int device_index;
	void __iomem *private_clkevt_base;
	struct list_head *ptr;
	struct timer_kit *entry;

	for (device_index = 0; device_index < max_sp804_instances;
		device_index++) {
		if (sp804_private_timer[device_index].
			devid[MINOR(pc->cdev.dev)] == pc->cdev.dev)
			break;
	}
	if (device_index == max_sp804_instances) {
		pr_debug("Unknown timer_delete call\n");
		return -1;
	}
	private_clkevt_base = sp804_private_timer[device_index].
				private_clkevt_base;
	if (MINOR(pc->cdev.dev) == 1)
		private_clkevt_base += TIMER_2_BASE;
	list_for_each(ptr,
			&sp804_private_timer[device_index].
			head[MINOR(pc->cdev.dev)]) {
		entry = list_entry(ptr, struct timer_kit, list);
		if (entry->kit == kit) {
			pr_debug("DELETE Value:%d\n", entry->value);
			list_del_init(&entry->list);
			kfree(entry);
			break;
		}
	}
	if (list_empty(&sp804_private_timer[device_index].
			head[MINOR(pc->cdev.dev)])) {
		/* Ensure timers are disabled */
		writel(0, private_clkevt_base + TIMER_CTRL);
		writel(0, private_clkevt_base + TIMER_2_BASE + TIMER_CTRL);
		sp804_private_timer[device_index].
			current_count[MINOR(pc->cdev.dev)] = 0;
		sp804_private_timer[device_index].
			prev_count[MINOR(pc->cdev.dev)] = 0;
	}
	return 0;
}

static void sp804_timer_gettime(struct posix_clock *pc,
				struct k_itimer *kit, struct itimerspec *tsp)
{
	void __iomem *private_clkevt_base;
	u32 current_value;
	struct itimerspec tsp_value;
	int device_index;
	long rate;
	unsigned long rate_mhz;
	unsigned long clk_div;
	unsigned long pre_scale;
	unsigned long time_micro;
	struct list_head *ptr;
	struct timer_kit *entry;

	/* pr_debug("recieved devid : %d\n",  pc->cdev.dev); */
	for (device_index = 0; device_index < max_sp804_instances;
		device_index++) {
		if (sp804_private_timer[device_index].
			devid[MINOR(pc->cdev.dev)] == pc->cdev.dev)
			break;
	}
	if (device_index == max_sp804_instances) {
		pr_debug("Unknown gettimer call\n");
		return;
	}
	private_clkevt_base = sp804_private_timer[device_index].
				private_clkevt_base;
	if (MINOR(pc->cdev.dev) == 1)
		private_clkevt_base += TIMER_2_BASE;
	rate = sp804_private_timer[device_index].rate[MINOR(pc->cdev.dev)];
	clk_div = sp804_private_timer[device_index].
			clk_div[MINOR(pc->cdev.dev)];
	pre_scale = sp804_private_timer[device_index].
			pre_scale[MINOR(pc->cdev.dev)];
	rate_mhz = DIV_ROUND_CLOSEST(rate, 1000000);
	tsp->it_interval.tv_sec = 0;
	tsp->it_interval.tv_nsec = 0;
	tsp->it_value.tv_sec = 0;
	tsp->it_value.tv_nsec = 0;
	list_for_each(ptr,
		      &sp804_private_timer[device_index].
			head[MINOR(pc->cdev.dev)]) {
		entry = list_entry(ptr, struct timer_kit, list);
		if ((entry->kit == kit) && (entry->status == ACTIVE)) {
			current_value = entry->left_ticks *
			    sp804_private_timer[device_index].
				granularity_us[MINOR(pc->cdev.dev)];
			pr_debug("left_ticks:%u gran:%u current_value :%u:\n",
				entry->left_ticks,
				sp804_private_timer[device_index].
				granularity_us[MINOR(pc->cdev.dev)],
				current_value);
			time_micro = current_value;

			if (entry->periodic == 0) {
				tsp->it_value.tv_sec = time_micro / 1000000;
				tsp->it_value.tv_nsec = (time_micro % 1000000)
				    * 1000;
				pr_debug("OneShot:sp804_timer_gettime ");
				pr_debug("DevId:%d %ld %ld\n",
					pc->cdev.dev,
					tsp_value.it_value.tv_sec,
					tsp_value.it_value.tv_nsec);
			} else {
				tsp->it_interval.tv_sec = time_micro / 1000000;
				tsp->it_interval.tv_nsec =
				    (time_micro % 1000000) * 1000;
				pr_debug("Interval sp804_timer_gettime ");
				pr_debug("DevId:%d %ld %ld\n",
					pc->cdev.dev,
					tsp_value.it_interval.tv_sec,
					tsp_value.it_interval.tv_nsec);
			}
			break;
		}
	}
}

static int sp804_timer_settime(struct posix_clock *pc,
			       struct k_itimer *kit, int flags,
			       struct itimerspec *tsp, struct itimerspec *old)
{
	void __iomem *private_clkevt_base;
	int device_index;
	long rate;
	unsigned long ctrl = TIMER_CTRL_32BIT | TIMER_CTRL_IE;
	unsigned long rate_mhz;
	unsigned long time_micro;
	unsigned long reload_value;
	unsigned long clk_div;
	unsigned long pre_scale;
	struct timer_kit *new_kit;

	pr_debug("recieved devid : %d\n", pc->cdev.dev);
	for (device_index = 0; device_index < max_sp804_instances;
		device_index++) {
		if (sp804_private_timer[device_index].
			devid[MINOR(pc->cdev.dev)] == pc->cdev.dev)
			break;
	}
	if (device_index == max_sp804_instances) {
		pr_debug("Unknown settimer call\n");
		return -1;
	}
	rate = sp804_private_timer[device_index].rate[MINOR(pc->cdev.dev)];
	clk_div = sp804_private_timer[device_index].
			clk_div[MINOR(pc->cdev.dev)];
	pre_scale = sp804_private_timer[device_index].
			pre_scale[MINOR(pc->cdev.dev)];
	private_clkevt_base = sp804_private_timer[device_index].
				private_clkevt_base;
	if (MINOR(pc->cdev.dev) == 1)
		private_clkevt_base += TIMER_2_BASE;

	rate_mhz = DIV_ROUND_CLOSEST(rate, 1000000);
	if (list_empty(&sp804_private_timer[device_index].
			head[MINOR(pc->cdev.dev)])) {
		time_micro =
		    sp804_private_timer[device_index].granularity_us[MINOR
							      (pc->cdev.dev)];
		pr_debug("DevId:%d", pc->cdev.dev);
		pr_debug(" rate:%ld tsp:%ld rate_mhz:%ld time_micro:%ld\n",
			rate,
			tsp->it_value.tv_sec + tsp->it_value.tv_nsec,
			rate_mhz,
			time_micro);
		ctrl |= TIMER_CTRL_PERIODIC | TIMER_CTRL_ENABLE;
		pr_debug("Periodic timer\n");
		reload_value = rate_mhz * time_micro;
		reload_value =
		    DIV_ROUND_CLOSEST(reload_value, clk_div * pre_scale);
		switch (pre_scale) {
		case 16:
			ctrl |= TIMER_CTRL_DIV16;
			break;
		case 256:
			ctrl |= TIMER_CTRL_DIV256;
			break;
		case 1:
		default:
			ctrl |= TIMER_CTRL_DIV1;
		}

		pr_debug("Ctrl:%x\n ", readl(private_clkevt_base + TIMER_CTRL));
		pr_debug("Load:%x\n ", readl(private_clkevt_base + TIMER_LOAD));
		pr_debug("reload value :%lx\n", reload_value);
		writel(reload_value, private_clkevt_base + TIMER_LOAD);
		writel(ctrl, private_clkevt_base + TIMER_CTRL);

		pr_debug("Ctrl:%x\n ", readl(private_clkevt_base + TIMER_CTRL));
		pr_debug("Load:%x\n ", readl(private_clkevt_base + TIMER_LOAD));
	}
	time_micro = DIV_ROUND_CLOSEST((tsp->it_value.tv_sec * 1000000000 +
					tsp->it_value.tv_nsec), 1000);
	new_kit = kzalloc(sizeof(struct timer_kit), GFP_KERNEL);
	new_kit->kit = kit;
	if (time_micro == 0) {
		new_kit->periodic = 1;
		new_kit->required_ticks =
		    (tsp->it_interval.tv_sec * 1000000000 +
		     tsp->it_interval.tv_nsec) /
		    (sp804_private_timer[device_index].granularity_us
		     [MINOR(pc->cdev.dev)] * 1000);
	} else {
		new_kit->periodic = 0;
		new_kit->required_ticks =
		    (tsp->it_value.tv_sec * 1000000000 +
		     tsp->it_value.tv_nsec) /
		    (sp804_private_timer[device_index].granularity_us
		     [MINOR(pc->cdev.dev)] * 1000);
	}
	new_kit->value = new_kit->required_ticks;
	new_kit->left_ticks = new_kit->required_ticks;
	new_kit->status = ACTIVE;
	list_add(&new_kit->list,
		 &sp804_private_timer[device_index].head[MINOR(pc->cdev.dev)]);
	pr_debug("ticks:%u:%u\n", new_kit->required_ticks, new_kit->left_ticks);
	return 0;
}

static struct posix_clock_operations sp804_timer_clock_ops = {
	.owner = THIS_MODULE,
	.timer_create = sp804_timer_create,
	.timer_delete = sp804_timer_delete,
	.timer_gettime = sp804_timer_gettime,
	.timer_settime = sp804_timer_settime,
};

struct sp804_timer_clock {
	struct posix_clock clock;
	struct device *dev;
	dev_t devid;
	int index;
};

static void delete_sp804_timer_clock(struct posix_clock *pc)
{
	pr_debug("delete_sp804_timer_clock\n");
}

static void process_timer_event(unsigned long dev_instance_subindex)
{
	int device;
	int device_subindex;
	struct siginfo info;
	struct task_struct *current_task;
	struct k_itimer *kit;
	struct list_head *ptr;
	struct timer_kit *entry;
	u32 lapsed_ticks;

	pr_debug("dev_instance_subindex:%lx\n", dev_instance_subindex);
	device = dev_instance_subindex / 2;
	device_subindex = dev_instance_subindex % 2;
	pr_debug("device:%d device_subindex:%d\n",
		 device, device_subindex);
	if (sp804_private_timer[device].current_count[device_subindex] <
	    sp804_private_timer[device].prev_count[device_subindex])
		lapsed_ticks = 0xFFFFFFFF -
				(sp804_private_timer[device].
					prev_count[device_subindex] -
				sp804_private_timer[device].
					current_count[device_subindex]);
	else
		lapsed_ticks = sp804_private_timer[device].
				current_count[device_subindex] -
				sp804_private_timer[device].
					prev_count[device_subindex];
	sp804_private_timer[device].prev_count[device_subindex] =
	    sp804_private_timer[device].current_count[device_subindex];
	list_for_each(ptr,
		      &sp804_private_timer[device].
		      head[device_subindex]) {
		entry = list_entry(ptr, struct timer_kit, list);
		kit = entry->kit;
		if ((lapsed_ticks > entry->left_ticks) &&
		    (entry->status == ACTIVE)) {
			memset(&info, 0, sizeof(struct siginfo));
			info.si_signo = kit->sigq->info.si_signo;
			info.si_code = kit->sigq->info.si_code;
			info.si_int = kit->sigq->info.si_int;
			rcu_read_lock();
			current_task = pid_task(kit->it_pid, PIDTYPE_PID);
			rcu_read_unlock();
			send_sig_info(kit->sigq->info.si_signo, &info,
				      current_task);
			if (entry->periodic == 1) {
				entry->left_ticks = entry->required_ticks;
			} else {
				entry->left_ticks = 0;
				entry->status = DEACTIVE;
			}
		} else {
			entry->left_ticks -= lapsed_ticks;
			pr_debug("Value:%d left_ticks:%u\n",
				entry->value, entry->left_ticks);
		}
	}
}

DECLARE_TASKLET(process_timer0_0, process_timer_event, 0);
DECLARE_TASKLET(process_timer0_1, process_timer_event, 1);
DECLARE_TASKLET(process_timer1_0, process_timer_event, 2);
DECLARE_TASKLET(process_timer1_1, process_timer_event, 3);
DECLARE_TASKLET(process_timer2_0, process_timer_event, 4);
DECLARE_TASKLET(process_timer2_1, process_timer_event, 5);
DECLARE_TASKLET(process_timer3_0, process_timer_event, 6);
DECLARE_TASKLET(process_timer3_1, process_timer_event, 7);

static irqreturn_t sp804_private_timer_interrupt(int irq, void *dev_id)
{
	void __iomem *private_clkevt_base;
	int loop;
	bool interrupt_received;
	struct private_timer *sp804_local_private_timer = dev_id;
	int device;
	int device_subindex;

	for (loop = 0; loop < DUAL_TIMER; loop++) {
		private_clkevt_base =
		    sp804_local_private_timer->private_clkevt_base;
		device = sp804_local_private_timer->dev_instance;
		if (readl(private_clkevt_base + TIMER_RIS) & 0x1) {
			device_subindex = 0;
			pr_debug("Interrupt from Timer1\n");
			interrupt_received = true;
		} else if (readl(private_clkevt_base + TIMER_2_BASE +
				 TIMER_RIS) & 0x1) {
			pr_debug("Interrupt from Timer2\n");
			device_subindex = 1;
			interrupt_received = true;
			private_clkevt_base += TIMER_2_BASE;
		} else {
			continue;
		}
		/* clear the interrupt */
		writel(1, private_clkevt_base + TIMER_INTCLR);
		pr_debug("Interrupt received %d\n", irq);
		if (!list_empty(&sp804_private_timer[device].
				head[device_subindex])) {
			sp804_private_timer[device].current_count
			    [device_subindex]++;
			switch (device * 2 + device_subindex) {
			case 0:
				tasklet_schedule(&process_timer0_0);
				break;
			case 1:
				tasklet_schedule(&process_timer0_1);
				break;
			case 2:
				tasklet_schedule(&process_timer1_0);
				break;
			case 3:
				tasklet_schedule(&process_timer1_1);
				break;
			case 4:
				tasklet_schedule(&process_timer2_0);
				break;
			case 5:
				tasklet_schedule(&process_timer2_1);
				break;
			case 6:
				tasklet_schedule(&process_timer3_0);
				break;
			case 7:
				tasklet_schedule(&process_timer3_1);
				break;
			}
		}
	}
	if (interrupt_received == false) {
		pr_warn("Spurious intr:%d received\n", irq);
		return IRQ_NONE;
	}
	return IRQ_HANDLED;
}

static int arm_private_timer_probe(struct platform_device *pdev)
{
	static int probed_device;
	struct device_node *np = pdev->dev.of_node;
	struct sp804_timer_clock *sp804_timer;
	int err;
	int major;
	int index;
	int irq;
	const char *name = of_get_property(np, "compatible", NULL);
	struct clk *clk1;
	struct clk *clk2;
	struct clk *pclk;
	long rate1;
	long rate2;
	long pclk_rate;
	u32 granularity_us;
	void __iomem *private_clkevt_base;
	char device_name[MAX_DEVICE_NAME_LEN];

	if (sp804_private_timer == NULL) {
		pr_debug("Allocating Memory for %d instances\n",
			 max_sp804_instances);
		sp804_private_timer = kzalloc(sizeof(private_timer) *
					      max_sp804_instances, GFP_KERNEL);
		if (sp804_private_timer == NULL) {
			pr_err("Allocation failed\n");
			return -ENOMEM;
		}
	}

	private_clkevt_base = of_iomap(np, 0);
	if (WARN_ON(!private_clkevt_base))
		return -ENOMEM;

	clk1 = of_clk_get(np, 0);
	if (IS_ERR(clk1))
		goto err;

	clk2 = of_clk_get(np, 1);
	if (IS_ERR(clk2))
		goto err;

	pclk = of_clk_get(np, 2);
	if (IS_ERR(pclk))
		goto err;

	irq = irq_of_parse_and_map(np, 0);
	if (irq <= 0)
		goto err;

	rate1 = sp804_get_clock_rate(clk1);
	if (rate1 < 0)
		goto err;

	rate2 = sp804_get_clock_rate(clk2);
	if (rate2 < 0)
		goto err;

	pclk_rate = sp804_get_clock_rate(pclk);
	if (pclk_rate < 0)
		goto err;

	pr_debug("probed_device :%d\n", probed_device);
	pr_debug("compatible:%s base:%p irq:%d rate1:%ld rate2:%ld\n",
		 name, private_clkevt_base, irq, rate1, rate2);

	sprintf(device_name, "%s.%d", MODULE_NAME, probed_device);
	err = alloc_chrdev_region(&sp804_private_timer[probed_device].
			sp804_timer_devt, 0, MINORMASK + 1, device_name);
	if (err < 0) {
		pr_err("sp804: failed to allocate device region\n");
		goto err;
	}

	/* Create a new device in our class. */
	sp804_private_timer[probed_device].sp804_timer_class =
	    class_create(THIS_MODULE, pdev->name);
	if (IS_ERR(sp804_private_timer[probed_device].sp804_timer_class)) {
		pr_err("SP804: failed to allocate class\n");
		goto err;
	}
	major = MAJOR(sp804_private_timer[probed_device].sp804_timer_devt);

	for (index = 0; index < DUAL_TIMER; index++) {
		sp804_timer = kzalloc(sizeof(struct sp804_timer_clock),
				      GFP_KERNEL);
		if (sp804_timer == NULL) {
			pr_err("Allocation failed\n");
			goto err;
		}
		sp804_timer->devid = MKDEV(major, index);
		sp804_timer->clock.ops = sp804_timer_clock_ops;
		sp804_timer->clock.release = delete_sp804_timer_clock;
		sp804_timer->index = index;

		register_chrdev_region(sp804_timer->devid, 1, MODULE_NAME);
		pr_debug("Device Creating in class %s id:%d\n",
			 pdev->name, sp804_timer->devid);
		sp804_timer->dev =
		    device_create(sp804_private_timer[probed_device].
				  sp804_timer_class, NULL, sp804_timer->devid,
				  sp804_timer, "sp804_timer.%d",
				  sp804_timer->index);
		if (IS_ERR(sp804_timer->dev)) {
			pr_err("Device Creation failed\n");
			goto err;
		} else {
			dev_set_drvdata(sp804_timer->dev, sp804_timer);
		}
		sp804_private_timer[probed_device].
		    sp804_timer_class->dev_groups = NULL;

		err = posix_clock_register(&sp804_timer->clock,
					   sp804_timer->devid);
		if (err < 0) {
			pr_err("sp804: posix clock registeration failed\n");
			goto err;
		}
		sp804_private_timer[probed_device].devid[index] =
		    sp804_timer->devid;

		if (!of_property_read_u32_index(np, "granularity-us",
						index, &granularity_us))
			sp804_private_timer[probed_device].granularity_us[index]
			    = granularity_us;
		else
			sp804_private_timer[probed_device].granularity_us[index]
			    = 1000000;
		sp804_private_timer[probed_device].current_count[index] = 0;
		sp804_private_timer[probed_device].prev_count[index] = 0;
		INIT_LIST_HEAD(&sp804_private_timer[probed_device].head[index]);
	}

	/* Ensure timers are disabled */
	writel(0, private_clkevt_base + TIMER_CTRL);
	writel(0, private_clkevt_base + TIMER_2_BASE + TIMER_CTRL);

	sp804_private_timer[probed_device].sp804_private_timer_irq.name =
	    "private timer";
	sp804_private_timer[probed_device].sp804_private_timer_irq.flags =
	    IRQF_TIMER | IRQF_IRQPOLL;
	sp804_private_timer[probed_device].sp804_private_timer_irq.handler =
	    sp804_private_timer_interrupt;
	sp804_private_timer[probed_device].sp804_private_timer_irq.dev_id =
	    &sp804_private_timer[probed_device];
	setup_irq(irq,
		  &sp804_private_timer[probed_device].sp804_private_timer_irq);

	sp804_private_timer[probed_device].private_clkevt_base =
	    private_clkevt_base;
	sp804_private_timer[probed_device].rate[0] = rate1;
	sp804_private_timer[probed_device].clk_div[0] =
	    DIV_ROUND_CLOSEST(pclk_rate, rate1);
	sp804_private_timer[probed_device].pre_scale[0] = timer1_pre_scale;
	sp804_private_timer[probed_device].rate[1] = rate2;
	sp804_private_timer[probed_device].clk_div[1] =
	    DIV_ROUND_CLOSEST(pclk_rate, rate2);
	sp804_private_timer[probed_device].pre_scale[1] = timer2_pre_scale;
	sp804_private_timer[probed_device].irq = irq;
	sp804_private_timer[probed_device].dev_instance = probed_device;
	pr_info("granularity0:%u micro-seconds granularity1:%u micro-seconds\n",
		sp804_private_timer[probed_device].granularity_us[0],
		sp804_private_timer[probed_device].granularity_us[1]);

	probed_device++;
	pr_info("Registered Arm Dual Timer SP804's Node :%s:", pdev->name);
	pr_info("As private timer with Major:%d Minor:0,1\n", major);

	return 0;
err:
	iounmap(private_clkevt_base);
	return -ENOMEM;
}

static const struct of_device_id arm_private_timer_of_match[] = {
	{.compatible = "arm,sp804_private_timer"},
	{ /* sentinel */ }
};

MODULE_DEVICE_TABLE(of, arm_private_timer_of_match);

static struct platform_driver arm_private_timer_driver = {
	.driver = {
			.name = "arm-sp804-private-timer",
			.of_match_table = arm_private_timer_of_match,
		  },
	.probe = arm_private_timer_probe,
};

module_platform_driver(arm_private_timer_driver);
