/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 Microchip.
 */

#ifndef __DRIVERS_RTC_H
#define __DRIVERS_RTC_H

#include <stdbool.h>
#include <tee_api.h>
#include <util.h>

/* The RTC allows to set/get offset for correction */
#define RTC_CORRECTION_FEATURE	BIT(0)
/* The RTC allows to set/read an alarm */
#define RTC_ALARM_FEATURE	BIT(1)
/* The RTC can wake-up the platform through alarm */
#define RTC_WAKEUP_ALARM	BIT(2)

struct optee_rtc_time {
	uint32_t tm_year;
	uint32_t tm_mon;
	uint32_t tm_mday;
	uint32_t tm_hour;
	uint32_t tm_min;
	uint32_t tm_sec;
	uint32_t tm_wday;
};

struct rtc {
	const struct rtc_ops *ops;
	struct optee_rtc_time range_min;
	struct optee_rtc_time range_max;
	bool is_wakeup_source;
};

/*
 * struct optee_rtc_alarm - The RTC alarm
 * @enabled:		1 if the alarm is enabled, 0 otherwise
 * @pending:		1 if the alarm is pending, 0 otherwise
 * @time:		The alarm time
 */
struct optee_rtc_alarm {
	uint8_t enabled;
	uint8_t pending;
	struct optee_rtc_time time;
};

/*
 * enum rtc_wait_alarm_status - Return status of the wait for the RTC alarm
 * @RTC_WAIT_ALARM_RESET:		Reset the wait for the RTC alarm
 * @RTC_WAIT_ALARM_ALARM_OCCURRED:	The RTC alarm occurred
 * @RTC_WAIT_ALARM_CANCELED:		The wait for the RTC alarm was canceled
 */
enum rtc_wait_alarm_status {
	RTC_WAIT_ALARM_RESET = 0x0,
	RTC_WAIT_ALARM_ALARM_OCCURRED = 0x1,
	RTC_WAIT_ALARM_CANCELED = 0x2,
};

/*
 * struct rtc_ops - The RTC device operations
 *
 * @get_time:	Get the RTC time.
 * @set_time:	Set the RTC time.
 * @get_offset:	Get the RTC offset.
 * @set_offset: Set the RTC offset
 * @read_alarm:	Read the RTC alarm
 * @set_alarm:	Set the RTC alarm
 * @enable_alarm: Enable the RTC alarm
 * @wait_alarm:	Wait for the RTC alarm
 * @cancel_wait: Cancel the wait for the RTC alarm
 * @set_alarm_wakeup_status: Set the wakeup capability of the alarm
 */
struct rtc_ops {
	TEE_Result (*get_time)(struct rtc *rtc, struct optee_rtc_time *tm);
	TEE_Result (*set_time)(struct rtc *rtc, struct optee_rtc_time *tm);
	TEE_Result (*get_offset)(struct rtc *rtc, long *offset);
	TEE_Result (*set_offset)(struct rtc *rtc, long offset);
	TEE_Result (*read_alarm)(struct rtc *rtc, struct optee_rtc_alarm *alrm);
	TEE_Result (*set_alarm)(struct rtc *rtc, struct optee_rtc_alarm *alrm);
	TEE_Result (*enable_alarm)(struct rtc *rtc, bool enable);
	TEE_Result (*wait_alarm)(struct rtc *rtc,
				 enum rtc_wait_alarm_status *status);
	TEE_Result (*cancel_wait)(struct rtc *rtc);
	TEE_Result (*set_alarm_wakeup_status)(struct rtc *rtc, bool status);
};

/**
 * rtc_is_a_leap_year() - Check if a year is a leap year
 * @year:	The year to check
 *
 * Return:	true if the year is a leap year, false otherwise
 */
bool rtc_is_a_leap_year(uint32_t year);

/**
 * rtc_get_month_days() - Get the number of days in a month
 * @month:	The month to know the number of days
 * @year:	The year of the month
 *
 * Return:	Number of days in the month
 */
uint8_t rtc_get_month_days(uint32_t month, uint32_t year);

/**
 * rtc_timecmp() - Compare two RTC time structures
 * @a:		First RTC time
 * @b:		Second RTC time
 *
 * Return a negative value if a < b
 * Return 0 if a == b
 * Return a positive value if a > b
 */
int rtc_timecmp(struct optee_rtc_time *a, struct optee_rtc_time *b);

#ifdef CFG_DRIVERS_RTC
extern struct rtc *rtc_device;

/* Register a RTC device as the system RTC */
void rtc_register(struct rtc *rtc);

static inline TEE_Result rtc_get_info(uint64_t *features,
				      struct optee_rtc_time *range_min,
				      struct optee_rtc_time *range_max)
{
	if (!rtc_device)
		return TEE_ERROR_NOT_SUPPORTED;

	if (rtc_device->ops->set_offset)
		*features = RTC_CORRECTION_FEATURE;
	*range_min = rtc_device->range_min;
	*range_max = rtc_device->range_max;

	if (rtc_device->ops->set_alarm)
		*features |= RTC_ALARM_FEATURE;

	if (rtc_device->is_wakeup_source)
		*features |= RTC_WAKEUP_ALARM;

	return TEE_SUCCESS;
}

static inline TEE_Result rtc_get_time(struct optee_rtc_time *tm)
{
	if (!rtc_device)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->get_time(rtc_device, tm);
}

static inline TEE_Result rtc_set_time(struct optee_rtc_time *tm)
{
	if (!rtc_device || !rtc_device->ops->set_time)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->set_time(rtc_device, tm);
}

static inline TEE_Result rtc_get_offset(long *offset)
{
	if (!rtc_device || !rtc_device->ops->get_offset)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->get_offset(rtc_device, offset);
}

static inline TEE_Result rtc_set_offset(long offset)
{
	if (!rtc_device || !rtc_device->ops->set_offset)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->set_offset(rtc_device, offset);
}

static inline TEE_Result rtc_read_alarm(struct optee_rtc_alarm *alarm)
{
	if (!rtc_device || !rtc_device->ops->read_alarm)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->read_alarm(rtc_device, alarm);
}

static inline TEE_Result rtc_set_alarm(struct optee_rtc_alarm *alarm)
{
	if (!rtc_device || !rtc_device->ops->set_alarm)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->set_alarm(rtc_device, alarm);
}

static inline TEE_Result rtc_enable_alarm(bool enable)
{
	if (!rtc_device || !rtc_device->ops->enable_alarm)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->enable_alarm(rtc_device, enable);
}

static inline TEE_Result rtc_wait_alarm(enum rtc_wait_alarm_status *status)
{
	if (!rtc_device || !rtc_device->ops->wait_alarm)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->wait_alarm(rtc_device, status);
}

static inline TEE_Result rtc_alarm_cancel_wait(void)
{
	if (!rtc_device || !rtc_device->ops->cancel_wait)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->cancel_wait(rtc_device);
}

static inline TEE_Result rtc_alarm_wake_set_status(int status)
{
	if (!rtc_device || !rtc_device->ops->set_alarm_wakeup_status)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->set_alarm_wakeup_status(rtc_device, status);
}
#else

static inline void rtc_register(struct rtc *rtc __unused) {}

static inline TEE_Result rtc_get_info(uint64_t *features __unused,
				      struct optee_rtc_time *range_min __unused,
				      struct optee_rtc_time *range_max __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result rtc_get_time(struct optee_rtc_time *tm __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result rtc_set_time(struct optee_rtc_time *tm __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result rtc_get_offset(long *offset __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result rtc_set_offset(long offset __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result rtc_read_alarm(struct optee_rtc_alarm *alarm __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result rtc_set_alarm(struct optee_rtc_alarm *alarm __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result rtc_enable_alarm(int enable __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result
rtc_wait_alarm(enum rtc_wait_alarm_status *status __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result rtc_alarm_cancel_wait(void)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result rtc_alarm_wakeup_set_status(int status __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif
#endif /* __DRIVERS_RTC_H */
