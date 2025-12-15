;(function() {
"use strict";
var __govContext = {
site: {},
page: {},
communicationBus: {},
};
// implementation of methods not available in IE
if (!String.prototype.startsWith) {
Object.defineProperty(String.prototype, 'startsWith', {
configurable: true,
value: function(search, rawPos) {
var pos = rawPos > 0 ? rawPos|0 : 0;
return this.substring(pos, pos + search.length) === search;
}
});
}
if (!String.prototype.endsWith) {
String.prototype.endsWith = function(search, this_len) {
if (this_len === undefined || this_len > this.length) {
this_len = this.length;
}
return this.substring(this_len - search.length, this_len) === search;
};
}
__govContext.site.locale = 'pl-PL';
__govContext.page.dict = {
'pagination.page': 'Strona',
'search.filters.dropdown.selected': 'Wybrane:',
'search.filters.dropdown.clear': 'Wyczyść',
'search.filters.period.option.7': 'Ostatnie 7 dni',
'search.filters.period.option.30': 'Ostatnie 30 dni',
'search.filters.period.option.90': 'Ostatnie 90 dni',
'search.filters.period.option.365': 'Ostatni rok',
'tooltip.see_more': 'Szczegółowe informacje',
};
__govContext.site_map = {};
__govContext.site_map.dict = {
'site_map.expand_subpages_tree': 'Rozwiń drzewo podstron {0} poziom {1}',
'site_map.expand': 'Rozwiń',
'site_map.collapse': 'Zwiń',
'site_map.expand_all': 'Rozwiń wszystko',
'site_map.collapse_all': 'Zwiń wszystko',
'site_map.show_pages': 'Pokaż tylko strony',
'site_map.show_bip_pages': 'Pokaż tylko strony BIP',
'site_map.show_all_pages': 'Pokaż wszystkie strony',
'site_map.find_page': 'Znajdź stronę',
'site_map.expand_image': '/img/icons/site-map/plus.svg',
'site_map.collapse_image': '/img/icons/site-map/minus.svg',
'site_map.find_page_image': '/img/icons/site-map/minus.svg',
'bip_icon_image': '/img/bip_simple.svg'
};
__govContext.pagination = {};
__govContext.pagination.dict = {
'pagination.perpage': 'Liczba wierszy:',
'pagination.prev.aria': 'Przejdź do poprzedniej strony wyników',
'pagination.prev': 'Poprzednia strona wyników',
'pagination.current.aria': 'Jesteś na stronie',
'pagination.move_to.aria': 'wyników Aby przejść do wybranej strony wyników Wpisz numer strony i naciśnij Enter',
'pagination.last.aria': 'Przejdź do ostatniej strony wyników',
'pagination.next.aria': 'Przejdź do następnej strony wyników',
'pagination.next': 'Następna strona wyników',
'pagination.perpage.sr_only': 'Pokaż {0} wierszy na stronę'
};
__govContext.datepicker = {};
__govContext.datepicker.dict = {
'datepicker.day_names': ["Niedziela","Poniedziałek","Wtorek","Środa","Czwartek","Piątek","Sobota"],
'datepicker.day_names_short': [ "Nie","Pn","Wt","Śr","Czw","Pt","So" ],
'datepicker.day_names_min': ["N", "P", "W", "Ś", "C", "P", "S"],
'datepicker.month_names': ["Styczeń", "Luty", "Marzec", "Kwiecień", "Maj", "Czerwiec", "Lipiec", "Sierpień", "Wrzesień", "Październik", "Listopad", "Grudzień"],
'datepicker.month_names_short': ["Sty", "Lut", "Mar", "Kwi", "Maj", "Cze", "Lip", "Sie", "Wrz", "Paź", "Lis", "Gru"],
'datepicker.close_text': 'Zamknij',
'datepicker.prev_text': 'Poprzedni miesiąc',
'datepicker.next_text': 'Następny miesiąc',
'datepicker.week_header': 'Tydz',
'datepicker.current_text': 'Dziś',
};
__govContext.announcement = {};
__govContext.announcement.dict = {
'announcement.js.event.days_ago': '%%days%% dni temu',
'annoucement.js.event.yesterday': 'Wczoraj',
'annoucement.js.event.today': 'Dzisiaj',
'annoucement.js.event.tomorrow': 'Jutro',
'annoucement.js.event.days_to': 'za %%days%% dni',
'annoucement.datepicker.no_announcement_in_this_month': 'Brak wydarzeń w wybranym miesiącu',
'annoucement.datepicker.no_announcement_on_this_day': 'Brak wydarzeń w tym dniu',
'annoucement.datepicker.number_announcement_on_this_day': 'Ilość wydarzeń w tym dniu',
'annoucement.datepicker.announcements': 'wydarzeń',
};
__govContext.widget = {};
__govContext.widget.dict = {
'widget.statistics.others': 'Pozostałe'
};
__govContext.bip = {
'address': 'https://aplikacje.gov.pl/app/bip-back'
};
__govContext.public_procurement_search = {
'form.subjects.all': 'Wszystkie'
};
__govContext.job_offers_search = {
'form.voivodeship.all': 'Wszystkie',
'job_offer.submission_date': 'Termin składania aplikacji:',
'job_offer.subject_name_unavailable': 'brak informacji o podmiocie'
};
var metas = document.getElementsByTagName('meta');
for (var i = 0; i < metas.length; i++) {
var key = metas[i].getAttribute('name') || metas[i].getAttribute('property');
if (key) {
if (key.startsWith('og:site_name')) {
__govContext.site.name = metas[i].getAttribute('content');
} else if (key.startsWith('govpl:site_')) {
__govContext.site[key.substring(11)] = metas[i].getAttribute('content');
} else if (key.startsWith('govpl:page_')) {
__govContext.page[key.substring(11)] = metas[i].getAttribute('content');
}
}
}
__govContext.contact_form = {
invalid_captcha_code: 'Błędny kod captcha. Proszę przepisać poprawną wartość z pola kod.',
constraints: {
"contactFormData\\.civilianMailAddress": {
presence: {
message: 'Pole adres E-mail jest wymagane.'
},
email: {
message: 'Podany adres e-mail jest niepoprawny.'
}
},
"contactFormData\\.messageContent": {
presence: {
message: 'Pole Treść wiadomośći jest wymagane.'
},
length: {
maximum: 1500,
message: 'Wprowadzony tekst jest za długi (maksymalna ilość znaków to 1500).'
}
},
"contactFormData\\.civilianName": {
presence: {
message: 'Pole Imię i nazwisko jest wymagane.'
}
},
'contactFormData\\.correspondenceAgreement': {
presence: {
message: 'Pole jest wymagane. Zaakceptuj zgodę.'
}
},
'contactFormData\\.rodoAgreement': {
presence: {
message: 'Pole jest wymagane. Zaakceptuj zgodę.'
}
},
'captcha-input-code': {
presence: {
message: 'Pole Captcha jest wymagane.'
},
captcha: true
}
}
};
window.__govContext = __govContext;
})();
