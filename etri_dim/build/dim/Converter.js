"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getRandomInt = exports.strToUtf8Arr = exports.byteArrToHexStr = exports.hexStrToByteArr = void 0;
var hexStrToByteArr = function (hexStr) {
    if (hexStr.trim() === "")
        return [];
    if (hexStr.length % 2 !== 0)
        throw Error("the length of a hex string must be even.");
    hexStr = hexStr.replace(/ /g, "");
    if (hexStr.slice(0, 2).toLowerCase() === "0x")
        hexStr = hexStr.slice(2, hexStr.length);
    var byteArr = [];
    var i = 0;
    var c = 0;
    var isEmpty = 1;
    var buffer = 0;
    for (i = 0; i < hexStr.length; i++) {
        c = hexStr.charCodeAt(i);
        if ((c > 47 && c < 58) || (c > 64 && c < 71) || (c > 96 && c < 103)) {
            buffer = (buffer << 4) ^ ((c > 64 ? c + 9 : c) & 15);
            if ((isEmpty ^= 1)) {
                byteArr.push(buffer & 0xff);
            }
        }
        else {
            throw Error("wrong hex string format");
        }
    }
    return byteArr;
};
exports.hexStrToByteArr = hexStrToByteArr;
var byteArrToHexStr = function (byteArr) {
    return Array.from(byteArr, function (byte) {
        return ("0" + (byte & 0xff).toString(16)).slice(-2);
    }).join("");
};
exports.byteArrToHexStr = byteArrToHexStr;
var strToUtf8Arr = function (str) {
    var utf8 = [];
    for (var i = 0; i < str.length; i++) {
        var charcode = str.charCodeAt(i);
        if (charcode < 0x80)
            utf8.push(charcode);
        else if (charcode < 0x800) {
            utf8.push(0xc0 | (charcode >> 6), 0x80 | (charcode & 0x3f));
        }
        else if (charcode < 0xd800 || charcode >= 0xe000) {
            utf8.push(0xe0 | (charcode >> 12), 0x80 | ((charcode >> 6) & 0x3f), 0x80 | (charcode & 0x3f));
        }
        // surrogate pair
        else {
            i++;
            charcode = ((charcode & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff);
            utf8.push(0xf0 | (charcode >> 18), 0x80 | ((charcode >> 12) & 0x3f), 0x80 | ((charcode >> 6) & 0x3f), 0x80 | (charcode & 0x3f));
        }
    }
    return utf8;
};
exports.strToUtf8Arr = strToUtf8Arr;
var getRandomInt = function (max) {
    return Math.floor(Math.random() * Math.floor(max));
};
exports.getRandomInt = getRandomInt;
//# sourceMappingURL=Converter.js.map