'use strict';
// RFC 8785 JSON Canonicalization Scheme (JCS).
// Numbers: ECMAScript Number::toString, which JSON.stringify implements exactly.
// Strings: JSON.stringify escaping (matches JCS for well-formed Unicode input).
// Object keys: sorted by UTF-16 code units (JavaScript's default string comparison).
function jcs(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new Error('JCS: non-finite number');
    return JSON.stringify(value);
  }
  if (t === 'boolean' || t === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (t === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(value[k])).join(',') + '}';
  }
  throw new Error('JCS: unsupported type ' + t);
}
module.exports = { jcs };
