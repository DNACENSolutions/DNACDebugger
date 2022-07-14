import functools
import logging
import re


def clean(msg):
    """
    Function for cleaning bash output.
    Removes control characters and carriage returns.

    :param str msg: Message to clean

    :return:    Clean message
    :rtype:     str
    """
    # (carriage returns | color codes | erase codes)
    regex = r'(\r|\x1b\[[0-9;]*m|\x1b\[[0-9]*K)'
    return re.sub(regex, '', msg)


def encapsulate(method):
    """
    Primary class decorator for convenience methods.

    - Encapsulates methods inside a single ssh connection.
    - Cleans out extraneous bash characters.
    - Logs input, output, and exceptions.
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        self.logger.info('Calling method `%s`.', method.__name__)
        try:
            if not self.is_connected:
                self.connect()
            out = method(self, *args, **kwargs)
        except Exception as err:
            self.logger.error(
                'Encountered error during excecution of `%s`',
                method.__name__,
            )
            self.logger.error(err, exc_info=True)
            msg = 'Last ssh response:\n' + self.get_ssh_last_response()
            self.logger.error(msg)
            raise
        finally:
            if self.is_connected and not self.persistent:
                self.logger.debug('Using non-persistent session...')
                self.disconnect()

        # Clean out bash control characters and carriage returns for string outputs
        if isinstance(out, str):
            out = clean(out)

        self.logger.debug('Method output:\n%s', repr(out))
        self.logger.info('Method `%s` returned successfully.', method.__name__)
        return out
    return wrapper


def log_kwargs(logger, msg, *kwargs_list, **kwargs):
    """
    Logs values in a keyword argument dictionary.
    Uses DEBUG level unless specified by a 'loglevel' kwarg.

    :param str msg:     Message to prefix the output.
    :param dict msg:    Keyword arguments to log.

    :return:    None
    """
    if 'loglevel' in kwargs:
        loglevel = kwargs['loglevel']
    else:
        loglevel = logging.DEBUG

    max_len = max(map(lambda kwargs: len(max(kwargs.keys(), key=len)), kwargs_list))
    if msg:
        msg += '\n'

    for kwargs in kwargs_list:
        for key, val in sorted(kwargs.items()):
            msg += '{}:'.format(key).ljust(max_len+2)
            msg += '{}\n'.format(val)

    if loglevel == logging.CRITICAL:
        logger.critical(msg.format(*kwargs))
    elif loglevel >= logging.ERROR:
        logger.error(msg.format(*kwargs))
    elif loglevel >= logging.WARNING:
        logger.warning(msg.format(*kwargs))
    elif loglevel >= logging.INFO:
        logger.info(msg.format(*kwargs))
    else:
        logger.debug(msg.format(*kwargs))


def parse_by_line_and_alert(logger, pattern, msg, alert_cond=None, alert_msg=''):
    """
    Parses string for a pattern, logging an alert if found.

    Notes:
        'alert_cond' is a function taking a dictionary which it will log, followed by each regex group from the pattern.
        'alert_cond' returns a bool indicating whether to alert.  (Return True if matching the pattern is enough).
        If 'alert_cond' is None (default), only returns pattern groups (no alert).
        If the pattern doesn't match, no alert occurs.

    :param logging.Logger logger:   Logger to log to.
    :param str pattern:             Regex string to match.  Alerts if found, passes all groups to 'alert_cond'.
    :param str msg:                 Message to parse.
    :param function alert_cond:     Function to call on alert.
    :param str alert_msg:           Message to print for the alert.

    :return:    Match groups found (if any)
    :rtype:     List
    """
    ret = []
    alerts = []
    for line in clean(msg).split('\n'):
        match = re.match(pattern, line)
        if match is not None:
            matchgroups = match.groups()
            ret.append(matchgroups)
            alert_group = {}
            if alert_cond and alert_cond(alert_group, *matchgroups):
                alerts.append(alert_group)
    if alerts:
        log_kwargs(logger, alert_msg, *alerts, loglevel=logging.WARNING)
    return ret

