"""Bounded SQL differential procedures. All response processing stays local."""
import html
import json
import re
from urllib.parse import parse_qsl, quote, quote_plus


PROFILES = ('sql_string', 'sql_numeric', 'sql_comment', 'sql_login')


def login_user_fields(request):
    """Identify account fields only in a submitted form with a password field."""
    if request.get('method') != 'POST':
        return []
    body = request.get('body') or ''
    try:
        fields = json.loads(body)
    except ValueError:
        fields = dict(parse_qsl(body, keep_blank_values=True))
    if not isinstance(fields, dict):
        return []
    names = [name for name in fields if isinstance(name, str)]
    if not any(re.search(r'pass|pwd|비밀번호', name, re.I) for name in names):
        return []
    return [name for name in names if re.search(
        r'user|login|email|account|uname|(?:^|[_-])uid$|^id$|아이디|계정', name, re.I)]


def probes(profile, base, round_index=0):
    # Independent constants and reversed order reduce accidental/reflected differences.
    yes, no = ('7319', '7321') if round_index == 0 else ('8461', '8467')
    if profile == 'sql_login':
        attacks = [
            {'role': 'byp_sql2', 'value': "admin'-- "},
            {'role': 'byp_sql', 'value': "' OR '1'='1'-- "},
        ]
        return [{'role': 'baseline', 'value': f'zzq_invalid_{yes}'},
                *(attacks if round_index == 0 else reversed(attacks))]
    if profile == 'sql_numeric':
        true, false = f'{base} AND {yes}={yes}', f'{base} AND {yes}={no}'
    elif profile == 'sql_comment':
        true = f"{base}' OR '{yes}'='{yes}'-- "
        false = f"{base}' AND '{yes}'='{no}'-- "
    elif profile == 'sql_string':
        true, false = f"{base}' AND '{yes}'='{yes}", f"{base}' AND '{yes}'='{no}"
    else:
        raise ValueError('Unknown SQL confirmation profile')
    pair = [{'role': 'bool_true', 'value': true}, {'role': 'bool_false', 'value': false}]
    return [{'role': 'baseline', 'value': base}, *(pair if round_index == 0 else reversed(pair))]


def without_reflection(body, value):
    """A reflected test input is not evidence of query evaluation."""
    if value:
        for spelling in sorted({value, html.escape(value), html.escape(value, quote=False),
                                quote(value, safe=''), quote_plus(value)}, key=len, reverse=True):
            body = body.replace(spelling, '[input]')
    return body
