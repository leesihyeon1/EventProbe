"""Local CVE / product recognition for SIEM log triage.

Reuses the Request/Analysis engine's request-only CVE fingerprinting
(`analyzer._cve_identify_from_request`) plus the device detection name. No
response body is needed, so it fits log records. Local rules only — no target
or AI calls. These are attack *attempts*, not success/compromise verdicts.
"""
import re

from core import analyzer   # request-only CVE fingerprint reused from 요청/분석 engine

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)

# CVE ID → 제품군. 요청 지문에 서버 메타가 비는 OOB 계열(Log4Shell 등)을 보완한다.
_CVE_PRODUCT = {
    'CVE-2021-44228': 'log4j', 'CVE-2021-45046': 'log4j', 'CVE-2021-45105': 'log4j',
    'CVE-2017-5638': 'struts', 'CVE-2018-11776': 'struts',
    'CVE-2022-22965': 'spring', 'CVE-2022-22963': 'spring',
    'CVE-2020-14882': 'weblogic', 'CVE-2020-14883': 'weblogic',
    'CVE-2019-19781': 'citrix', 'CVE-2023-4966': 'citrix',
    'CVE-2021-26084': 'confluence', 'CVE-2022-26134': 'confluence',
    'CVE-2021-41773': 'apache-httpd', 'CVE-2021-42013': 'apache-httpd',
    'CVE-2021-3129': 'laravel',
}

# 탐지명/서버 문자열에서 보이는 제품 키워드 → 제품군(정규화).
_PRODUCT_HINTS = (
    ('log4j', r'log4shell|log4j'), ('struts', r'struts'), ('spring', r'spring4shell|springframework|\bspring\b'),
    ('weblogic', r'weblogic'), ('citrix', r'citrix|netscaler'), ('confluence', r'confluence|atlassian'),
    ('exchange', r'proxyshell|proxylogon|\bexchange\b'), ('wordpress', r'wordpress|wp-'),
    ('apache-httpd', r'apache'), ('nginx', r'nginx'), ('tomcat', r'tomcat'),
)


def _product_from_text(text):
    text = (text or '').lower()
    for product, pattern in _PRODUCT_HINTS:
        if re.search(pattern, text):
            return product
    return ''


def identify(url='', req_body='', req_headers=None, signature=''):
    """한 레코드의 CVE ID·제품군을 추정한다.

    - source='device': 장비 탐지명에 CVE/제품명이 있음(신뢰 높음)
    - source='inferred': 요청 지문에서 추론(신뢰 중)
    원문/대상/AI 호출 없이 로컬 규칙만 사용한다.
    """
    cves, products, source = set(), set(), ''
    # 1) 장비 탐지명(신뢰 높음)
    for match in _CVE_RE.findall(signature or ''):
        cves.add(match.upper())
        source = 'device'
    signature_product = _product_from_text(signature)
    if signature_product:
        products.add(signature_product)
        source = source or 'device'
    # 2) 요청 지문 추론(신뢰 중) — 요청/분석 엔진 재사용
    for ident in analyzer._cve_identify_from_request(url or '', req_body or '', req_headers or {}):
        cve = (ident.get('cve') or '').upper()
        if not cve:
            continue
        cves.add(cve)
        product = _CVE_PRODUCT.get(cve) or _product_from_text(' '.join(ident.get('server') or []))
        if product:
            products.add(product)
        source = source or 'inferred'
    # CVE ID 로 제품군 보완(탐지명만 있던 경우 포함)
    for cve in cves:
        if cve in _CVE_PRODUCT:
            products.add(_CVE_PRODUCT[cve])
    return dict(cves=sorted(cves), products=sorted(p for p in products if p), source=source)
