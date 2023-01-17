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

#include <linux/init.h>
#include <linux/time.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/sched_clock.h>

#include <mach/opv5xc.h>


/* Timer */
#define NR_CYCLES_PER_TICK	(CLOCK_TICK_RATE/HZ)

static void __iomem *timer_base;
static u32 timer1_reload;
static u32 timer_mode;

static cycle_t timer2_get_cycles(struct clocksource *cs)
{
	return (cycle_t)readl(timer_base + TM2_COUNT_OFFSET);
}

static u32 notrace read_sched_clock(void)
{
	return (u32)timer2_get_cycles(NULL);
}

static struct clocksource timer2_clocksource = {
	.name	= "timer2",
	.rating	= 450,
	.read	= timer2_get_cycles,
	.mask	= CLOCKSOURCE_MASK(32),
	.shift	= 8,
	.flags	= CLOCK_SOURCE_VALID_FOR_HRES | CLOCK_SOURCE_IS_CONTINUOUS,
};

static void timer_set_mode(enum clock_event_mode mode, struct clock_event_device *evt)
{
	unsigned long ctrl = readl(timer_base + TM_CTRL_OFFSET);

	timer_mode = mode;

	switch (mode) {
	case CLOCK_EVT_MODE_PERIODIC:
		ctrl |= TM1_OF_ENABLE | TM1_CR | TM1_ENABLE;
		break;

	case CLOCK_EVT_MODE_ONESHOT:
		/* period set, and timer enabled in 'next_event' hook */
		ctrl &= ~(TM1_OF_ENABLE | TM1_ENABLE);
		break;

	case CLOCK_EVT_MODE_UNUSED:
	case CLOCK_EVT_MODE_SHUTDOWN:
	default:
		ctrl &= ~(TM1_ENABLE);
		break;
	}

	writel(ctrl | TM1_UPDATE, timer_base + TM_CTRL_OFFSET);
}

static int timer_set_next_event(unsigned long next, struct clock_event_device *evt)
{
	unsigned long ctrl = readl(timer_base + TM_CTRL_OFFSET);

	writel(next, timer_base + TM1_COUNT_OFFSET);
	writel(next, timer_base + TM1_RELOAD_OFFSET);
	writel((ctrl | TM1_UPDATE | TM1_OF_ENABLE | TM1_ENABLE), timer_base + TM_CTRL_OFFSET);

	return 0;
}

static struct clock_event_device opv5xc_timer_clockevent = {
	.shift		= 20,
	.features	= CLOCK_EVT_FEAT_PERIODIC | CLOCK_EVT_FEAT_ONESHOT,
	.set_mode	= timer_set_mode,
	.set_next_event	= timer_set_next_event,
	.rating		= 300,
	.cpumask	= cpu_all_mask,
};

static void __init opv5xc_clockevents_init(unsigned int timer_irq)
{
	struct clock_event_device *evt = &opv5xc_timer_clockevent;
	long rate = CLOCK_TICK_RATE;

	evt->name = "timer1";
	evt->irq = timer_irq;
	evt->mult = div_sc(rate, NSEC_PER_SEC, evt->shift);
	evt->max_delta_ns = clockevent_delta2ns(0xffffffff, evt);
	evt->min_delta_ns = clockevent_delta2ns(0xf, evt);
	evt->cpumask = cpumask_of(0);

	clockevents_register_device(evt);
}

static void __init opv5xc_clocksource_init(void)
{
	clocksource_register_hz(&timer2_clocksource, CLOCK_TICK_RATE);
}

static irqreturn_t opv5xc_timer_interrupt(int irq, void *dev_id)
{
	struct clock_event_device *evt = dev_id;
	u32 status, ctrl;

	status = readl(timer_base + TM_INTR_STATUS_OFFSET);
	ctrl = readl(timer_base + TM_CTRL_OFFSET);

	if (status & TM1_OF) {
		if (timer_mode == CLOCK_EVT_MODE_ONESHOT)
			writel(((ctrl & ~(TM1_ENABLE)) | TM1_UPDATE), timer_base + TM_CTRL_OFFSET);

		evt->event_handler(evt);
		writel((status & ~(TM1_OF)), timer_base + TM_INTR_STATUS_OFFSET);
	} else {
		writel(status, timer_base + TM_INTR_STATUS_OFFSET);
	}

	return IRQ_HANDLED;
}

static struct irqaction opv5xc_timer_irq = {
	.name		= "timer1",
	.flags		= IRQF_DISABLED | IRQF_TIMER | IRQF_IRQPOLL,
	.handler	= opv5xc_timer_interrupt,
	.dev_id		= &opv5xc_timer_clockevent,
};

void __init opv5xc_timer_init(void)
{
	unsigned int timer_irq = IRQ_OPV5XC_TIMER1;
	u32 u32tmp = 0;
	int cnt = 100;

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	/* clock enable */
	writel(readl(OPV5XC_CR_PMU_BASE_VIRT) & ~(1 << 14), OPV5XC_CR_PMU_BASE_VIRT);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) & ~(1 << 14)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) | (1 << 14)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel(readl(OPV5XC_CR_PMU_BASE_VIRT) | (1 << 14), OPV5XC_CR_PMU_BASE_VIRT);
	while (cnt--) {
		if (readl(OPV5XC_CR_PMU_BASE_VIRT + 0x10) & (1 << 14)) {
			u32tmp = 1;
			break;
		}
	}
#endif
	if (u32tmp == 0) {
		pr_err("Clock not enabled\n");
		return;
	} else
		u32tmp = 0;

	timer_base = ioremap(OPV5XC_TIMER_BASE, SZ_1K);

	/* Initialise to a known state (all timers off) */
	writel((0 | TM3_UPDATE | TM2_UPDATE | TM1_UPDATE), timer_base + TM_CTRL_OFFSET);
	writel(0, timer_base + FTM_CTRL_OFFSET);

	/* timer1 -- down counter, clockevent device */
	timer1_reload = NR_CYCLES_PER_TICK;
	writel(timer1_reload, timer_base + TM1_COUNT_OFFSET);
	writel(timer1_reload, timer_base + TM1_RELOAD_OFFSET);
	writel(0xffffffff, timer_base + TM1_MATCH1_OFFSET);
	writel(0xffffffff, timer_base + TM1_MATCH2_OFFSET);

	/* non-mask timer1 overflow irq */
	u32tmp = readl(timer_base + TM_INTR_MASK_OFFSET);
	u32tmp &= ~(TM1_OF_MASK);
	u32tmp |= (TM1_MATCH2_MASK | TM1_MATCH1_MASK);
	writel(u32tmp, timer_base + TM_INTR_MASK_OFFSET);

	/* timer2 -- periodic free-running clocksource, interrupt disabled */
	writel(0x0, timer_base + TM2_COUNT_OFFSET);
	writel(0x0, timer_base + TM2_RELOAD_OFFSET);
	writel(0xffffffff, timer_base + TM2_MATCH1_OFFSET);
	writel(0xffffffff, timer_base + TM2_MATCH2_OFFSET);

	/* mask all irqs */
	u32tmp = readl(timer_base + TM_INTR_MASK_OFFSET);
	u32tmp |= (TM2_OF_MASK | TM2_MATCH2_MASK | TM2_MATCH1_MASK);
	writel(u32tmp, timer_base + TM_INTR_MASK_OFFSET);

	/* timer2: enable up counter */
	u32tmp = readl(timer_base + TM_CTRL_OFFSET);
	u32tmp |= (TM2_UPDATE | TM2_ENABLE);
	writel(u32tmp, timer_base + TM_CTRL_OFFSET);

	/* fast timer */
	writel((FT_RUN | FT_RESET), timer_base + FTM_CTRL_OFFSET);

	/* Make irqs happen for the system timer */
	writel(0x000001ff, timer_base + TM_INTR_STATUS_OFFSET);

	irq_set_irq_type(timer_irq, IRQ_TYPE_EDGE_RISING);
	setup_irq(timer_irq, &opv5xc_timer_irq);

	setup_sched_clock(read_sched_clock, 32, CLOCK_TICK_RATE);
	opv5xc_clocksource_init();
	opv5xc_clockevents_init(timer_irq);
}
