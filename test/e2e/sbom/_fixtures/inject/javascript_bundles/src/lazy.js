import escapeStringRegexp from "escape-string-regexp";

export const pattern = (text) => new RegExp(escapeStringRegexp(text));
