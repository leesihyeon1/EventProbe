"""Local intent labels. Free-form task text never needs to leave the process."""
import re


_CATEGORIES = {
    'sqli': r'(?<![a-z])sql(?:i|\s*injection)?(?![a-z])|에스큐엘',
    'nosql': r'(?<![a-z])nosql(?![a-z])',
    'xss': r'(?<![a-z])xss(?![a-z])|크로스\s*사이트\s*스크립',
    'ssti': r'(?<![a-z])ssti(?![a-z])|템플릿\s*(?:주입|인젝션)',
    'ssrf': r'(?<![a-z])ssrf(?![a-z])',
    'lfi': r'(?<![a-z])(?:lfi|rfi)(?![a-z])|path\s+traversal|경로\s*조작',
    'cmdi': r'(?<![a-z])cmdi(?![a-z])|command\s+injection|명령(?:어)?\s*(?:주입|인젝션)',
    'redirect': r'open\s*redirect|오픈\s*리다이렉트',
}


def requested_categories(goal, structured_categories=()):
    explicit = set(structured_categories)
    if explicit:
        return explicit
    return {category for category, pattern in _CATEGORIES.items()
            if re.search(pattern, goal or '', re.IGNORECASE)}
