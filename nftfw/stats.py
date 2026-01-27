"""Statistics and time formatting utilities for nftfw.

This module provides utility functions for formatting time durations and
calculating event frequencies. Used primarily by the database listing
utilities (nftfwls, nftnetchk) to display human-readable time statistics
about blacklist entries and network blocks.

Functions:
    duration: Format time span between two timestamps
    frequency: Calculate event rate (per day/hour/minute)

Example:
    Displaying database entry statistics::

        from nftfw.stats import duration, frequency
        import time

        first_seen = 1636000000
        last_seen = 1636090000
        match_count = 150

        # Show how long the activity lasted
        dur = duration(first_seen, last_seen)
        print(f"Duration: {dur}")  # "1d 01h"

        # Show event frequency
        freq = frequency(first_seen, last_seen, match_count)
        print(f"Frequency: {freq}")  # "6/hr"

See Also:
    - nftfwls: Uses these functions for blacklist database display
    - nftnetchk: Uses these functions for network blacklist display
"""

from __future__ import annotations


def duration(first: int, last: int) -> str:
    """Format duration between two timestamps.

    Calculates the time span between two Unix timestamps and returns a
    human-readable formatted string. Only displays durations of 1 minute
    or longer. Uses compact format: days+hours, hours+minutes, or minutes only.

    Args:
        first: Unix timestamp of start time
        last: Unix timestamp of end time

    Returns:
        Formatted duration string:
        - "DDd HHh" for durations over 24 hours (e.g., " 5d 03h")
        - "HHh MMm" for durations over 1 hour (e.g., " 3h 45m")
        - "MMm" for durations over 1 minute (e.g., "15m")
        - Empty string for durations under 1 minute or if last <= first

    Example:
        Format various durations::

            duration(1000000, 1000060)   # ""        (1 minute, minimum threshold)
            duration(1000000, 1000120)   # "02m"     (2 minutes)
            duration(1000000, 1007200)   # " 2h 00m" (2 hours)
            duration(1000000, 1090800)   # " 1d 01h" (25 hours)
            duration(1090800, 1000000)   # ""        (negative, returns empty)
    """

    ret = ''
    diff = last - first
    if diff <= 0:
        return ''

    mm = divmod(diff, 60)[0]
    if mm == 0:
        # don't bother unless we have some minutes
        return ''

    hh, mm = divmod(mm, 60)
    if hh > 24:
        dd, hh = divmod(hh, 24)
        ret = f"{dd:2d}d {hh:02d}h"
    elif hh > 0:
        ret = f"{hh:2d}h {mm:02d}m"
    else:
        ret = f"{mm:02d}m"
    return ret


def frequency(first: int, last: int, count: int) -> str:
    """Calculate event frequency between two timestamps.

    Computes the rate of events (per day, hour, or minute) based on the
    time span and event count. Automatically selects appropriate units
    and may show multiple scales for high-frequency events.

    Args:
        first: Unix timestamp of first event
        last: Unix timestamp of last event
        count: Number of events in the time span

    Returns:
        Formatted frequency string:
        - "N/day" for spans over 24 hours
        - "N/hr" for spans over 1 hour
        - "N/min" for spans over 1 minute
        - Multiple scales for high rates (e.g., "150/day 6/hr")
        - Empty string for spans under 1 minute or if last <= first

    Example:
        Calculate various frequencies::

            # 100 events over ~1 day
            frequency(1000000, 1086400, 100)   # "1/day"

            # 1000 events over ~1 day
            frequency(1000000, 1086400, 1000)  # "11/day"

            # 2000 events over ~1 day (high frequency, multiple scales)
            frequency(1000000, 1086400, 2000)  # "23/day"

            # 500 events over 2 hours
            frequency(1000000, 1007200, 500)   # "250/hr 4/min"

            # 100 events over 30 minutes
            frequency(1000000, 1001800, 100)   # "3/min"
    """

    ret = ''
    diff = last - first
    if diff <= 0:
        return ret

    mm = divmod(diff, 60)[0]
    # don't bother unless we have some minutes
    if mm == 0:
        return ret

    hh = divmod(mm, 60)[0]
    if hh > 24:
        # days
        dd = divmod(hh, 24)[0]
        freq = divmod(count, dd)[0]
        r = []
        if freq > 0:
            r.append(f'{freq}/day')

            if freq > 24:
                perh = divmod(freq, 24)[0]
                r.append(f'{perh}/hr')

                if perh > 60:
                    perm = divmod(perh, 60)[0]
                    r.append(f'{perm}/min')

            ret = " ".join(r)
    elif hh > 0:
        # hours
        freq = divmod(count, hh)[0]
        r = []
        if freq > 0:
            r.append(f'{freq}/hr')

            if freq > 60:
                perm = divmod(freq, 60)[0]
                r.append(f'{perm}/min')

            ret = " ".join(r)
    else:
        # minutes
        freq = divmod(count, mm)[0]
        if freq > 0:
            ret = f'{freq}/min'
    return ret
