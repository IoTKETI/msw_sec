"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.OutInt = exports.OutShort = exports.OutByteArray = exports.OutByte = exports.OutObject = void 0;
var OutObject = /** @class */ (function () {
    function OutObject(value) {
        if (value)
            this.value = value;
        else
            this.value = null;
    }
    return OutObject;
}());
exports.OutObject = OutObject;
var OutByte = /** @class */ (function (_super) {
    __extends(OutByte, _super);
    function OutByte() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return OutByte;
}(OutObject));
exports.OutByte = OutByte;
var OutByteArray = /** @class */ (function (_super) {
    __extends(OutByteArray, _super);
    function OutByteArray() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return OutByteArray;
}(OutObject));
exports.OutByteArray = OutByteArray;
var OutShort = /** @class */ (function (_super) {
    __extends(OutShort, _super);
    function OutShort() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return OutShort;
}(OutObject));
exports.OutShort = OutShort;
var OutInt = /** @class */ (function (_super) {
    __extends(OutInt, _super);
    function OutInt() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return OutInt;
}(OutObject));
exports.OutInt = OutInt;
//# sourceMappingURL=OutObject.js.map