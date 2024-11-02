""" nftfw - statistics """

def duration(first, last):
    """Evaluate duration

    Parameters
    ----------
    first : int
        First timestamp
    last : int
        Last timestamp

    Returns
    -------
    str
        Formatted string
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
        #ret = "%2dd %02dh" % (dd, hh)
        ret = f"{dd:2d}d {hh:02d}h"
    elif hh > 0:
        #ret = "%2dh %02dm" % (hh, mm)
        ret = f"{hh:2d}h {mm:02d}m"
    else:
        #ret = "%02dm" % (mm)
        ret = f"{mm:02d}m"
    return ret

def frequency(first, last, count):
    """Evaluate frequency

    Parameters
    ----------
    first : int
        First timestamp
    last : int
        Last timestamp
    count : int
        Count we are looking at

    Returns
    -------
    str
        Frequency or ''

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
