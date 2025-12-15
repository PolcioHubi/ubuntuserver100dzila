"use strict";

var registerMetadata = getPreValue('pageMetadata', true).register;
var registersMap = {};
registerMetadata.columns.filter(function (c) {
  return c.showInContent;
}).forEach(function (c) {
  return registersMap[c.registerId] = {
    selector: c.positionSelector,
    method: c.insertMethod
  };
});
Object.keys(registersMap).forEach(function (registerId) {
  var firstElement = $(registersMap[registerId].selector)[0];

  if (firstElement) {
    var movedElement = $(".register-columns-".concat(registerId));
    movedElement.removeClass('hide');
    $(firstElement)[registersMap[registerId].method](movedElement.remove());
  }
});
