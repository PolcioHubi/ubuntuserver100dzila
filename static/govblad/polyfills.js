"use strict";

Array.prototype.findIndex || Object.defineProperty(Array.prototype, "findIndex", {
  value: function value(r) {
    if (null == this) throw new TypeError('"this" is null or not defined');
    var t = Object(this),
        e = t.length >>> 0;
    if ("function" != typeof r) throw new TypeError("predicate must be a function");

    for (var n = arguments[1], i = 0; i < e;) {
      var o = t[i];
      if (r.call(n, o, i, t)) return i;
      i++;
    }

    return -1;
  },
  configurable: !0,
  writable: !0
}), String.prototype.padStart || (String.prototype.padStart = function (r, t) {
  return r >>= 0, t = String(void 0 !== t ? t : " "), this.length > r ? String(this) : ((r -= this.length) > t.length && (t += t.repeat(r / t.length)), t.slice(0, r) + String(this));
}), Array.from || (Array.from = function () {
  var r = Object.prototype.toString,
      t = function t(_t) {
    return "function" == typeof _t || "[object Function]" === r.call(_t);
  },
      e = Math.pow(2, 53) - 1,
      n = function n(r) {
    var t = function (r) {
      var t = Number(r);
      return isNaN(t) ? 0 : 0 !== t && isFinite(t) ? (t > 0 ? 1 : -1) * Math.floor(Math.abs(t)) : t;
    }(r);

    return Math.min(Math.max(t, 0), e);
  };

  return function (r) {
    var e = Object(r);
    if (null == r) throw new TypeError("Array.from requires an array-like object - not null or undefined");
    var i,
        o = arguments.length > 1 ? arguments[1] : void 0;

    if (void 0 !== o) {
      if (!t(o)) throw new TypeError("Array.from: when provided, the second argument must be a function");
      arguments.length > 2 && (i = arguments[2]);
    }

    for (var a, u = n(e.length), f = t(this) ? Object(new this(u)) : new Array(u), p = 0; p < u;) {
      a = e[p], f[p] = o ? void 0 === i ? o(a, p) : o.call(i, a, p) : a, p += 1;
    }

    return f.length = u, f;
  };
}()), Array.prototype.find || Object.defineProperty(Array.prototype, "find", {
  value: function value(r) {
    if (null == this) throw TypeError('"this" is null or not defined');
    var t = Object(this),
        e = t.length >>> 0;
    if ("function" != typeof r) throw TypeError("predicate must be a function");

    for (var n = arguments[1], i = 0; i < e;) {
      var o = t[i];
      if (r.call(n, o, i, t)) return o;
      i++;
    }
  },
  configurable: !0,
  writable: !0
}), String.prototype.includes || (String.prototype.includes = function (r, t) {
  "use strict";

  if (r instanceof RegExp) throw TypeError("first argument must not be a RegExp");
  return void 0 === t && (t = 0), -1 !== this.indexOf(r, t);
}), Array.prototype.includes || (Array.prototype.includes = function (r) {
  "use strict";

  var t = Object(this),
      e = parseInt(t.length) || 0;
  if (0 === e) return !1;
  var n,
      i,
      o = parseInt(arguments[1]) || 0;

  for (o >= 0 ? n = o : (n = e + o) < 0 && (n = 0); n < e;) {
    if (r === (i = t[n]) || r != r && i != i) return !0;
    n++;
  }

  return !1;
});
