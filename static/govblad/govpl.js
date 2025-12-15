"use strict";

;

(function () {
  var SHOW_MENU_CLASS = 'js-show-gov-menu';
  var DISABLE_ANIMATION_CLASS = 'js-disable-animation-gov-menu';

  function initializeBarHiding() {
    var root = document.body && document.body.scrollTop ? document.body : document.documentElement;
    var body = document.getElementById('body');
    var lastScrollTop = 10000;
    document.addEventListener('scroll', function (event) {
      var scrollTop = root.scrollTop;

      if (scrollTop > lastScrollTop && scrollTop > 80 && !hasClass(body, SHOW_MENU_CLASS)) {
        if (scrollTop > lastScrollTop + 10) {
          addClass(body, 'js-hide-gov-bar');
        }
      } else {
        removeClass(body, 'js-hide-gov-bar');
      }

      lastScrollTop = scrollTop;
    });
  }

  function initializeHamburger() {
    var MIN_DESK_CSS_BREAKPOINT = 1280;
    var desk = window.innerWidth >= MIN_DESK_CSS_BREAKPOINT;
    var target = document.getElementById('body');
    var menuOpener = $('.govpl__menu-opener')[0];

    if (!toggler) {
      // if template is not using hamburger menu
      return;
    }

    var toggle = function toggle(event) {
      var opening = !hasClass(target, SHOW_MENU_CLASS);
      opening ? addClass(target, SHOW_MENU_CLASS) : removeClass(target, SHOW_MENU_CLASS);
      toggler.setAttribute('aria-expanded', opening);

      if (event) {
        event.preventDefault();
        event.stopPropagation();
        desk && setCookie('gov-hamburger', opening ? 'yes' : 'no');
      }
    };

    window.govpl._past_toggle && toggler.removeEventListener('click', window.govpl._past_toggle);
    toggler.addEventListener('click', toggle);
    window.govpl._past_toggle = toggle;
    var govClose = document.querySelector('.govpl-menu__close');
    govClose.addEventListener('click', function () {
      removeClass(target, SHOW_MENU_CLASS);
      toggler.setAttribute('aria-expanded', 'false');
      toggler.focus();
    });
    toggler.addEventListener('resize', function (e) {
      if (desk !== this.innerWidth >= MIN_DESK) {
        var opened = hasClass(target, SHOW_MENU_CLASS);
        desk = !desk;

        if (getCookie('gov-hamburger') === 'yes') {
          if (!desk || desk && !opened) {
            toggle();
          }
        } else {
          if (desk && opened) {
            setCookie('gov-hamburger', 'yes');
          }
        }
      }
    });
    var govmenu = document.getElementById('gov-menu-nav');

    if (govmenu && window.innerWidth >= MIN_DESK_CSS_BREAKPOINT && getCookie('gov-hamburger') !== 'no') {
      addClass(target, DISABLE_ANIMATION_CLASS);
      addClass(target, SHOW_MENU_CLASS);
      setTimeout(function () {
        removeClass(target, DISABLE_ANIMATION_CLASS);
      }, 400);
    }
  }

  function addClass(element, className) {
    var arr = element.className.split(" ");

    if (arr.indexOf(className) == -1) {
      element.className += " " + className;
    }
  }

  function removeClass(element, className) {
    element.className = element.className.replace(new RegExp('(?:^|\\s)' + className + '(?:\\s|$)'), ' ');
  }

  function hasClass(element, className) {
    return element.className.split(" ").indexOf(className) != -1;
  }

  function setCookie(name, value) {
    document.cookie = name + "=" + value + ';path=/';
  }

  function getCookie(name) {
    var value = "; " + document.cookie;
    var parts = value.split("; " + name + "=");
    if (parts.length == 2) return parts.pop().split(";").shift();
  }

  window.govpl = {
    initializeBarHiding: initializeBarHiding,
    initializeHamburger: initializeHamburger,
    addClass: addClass,
    removeClass: removeClass,
    hasClass: hasClass,
    setCookie: setCookie,
    getCookie: getCookie
  };
})();
