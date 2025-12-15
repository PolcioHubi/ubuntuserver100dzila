"use strict";

$(function () {
  $('.simple-accordion a.expand').click(function (e) {
    e.preventDefault();
    $(this).toggleClass('expanded');
    $(this).siblings('.info').toggleClass('expanded');
    $(this).find('i.fa').toggleClass('fa-chevron-down fa-chevron-up');
    var ariaExpanded = $(this).attr("aria-expanded") == "false" ? "true" : "false";
    $(this).attr("aria-expanded", ariaExpanded);
  });
  $('.simple-accordion-toggler a').click(function (e) {
    e.preventDefault();
    $('.simple-accordion a.expand:not(.expanded)').click();
  });
  $(document).on('click', '.js-scenario-content .data-table td:first-child', function (e) {
    if ($(e.target).is('a')) return;
    e.preventDefault();
    $(this).toggleClass('expanded');
  });
  $('.card--accordions__accordion').click(function (e) {
    $(this).children('.card--accordions__accordion--header').toggleClass('expanded');
    $(this).children('.card--accordions__accordion--text').toggleClass('expanded');
  });
});
