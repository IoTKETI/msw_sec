"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
/* eslint-disable prefer-const */
var node_hid_1 = __importDefault(require("node-hid"));
////////////////////////////////////////////////////////////////////////////////
//// Class : KseDim ////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
var KseDim = /** @class */ (function () {
    //// AMI /////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////
    //// Instance Constructor ////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////
    function KseDim(tlsReadHanldler, tlsWriteHanldler) {
        var _this = this;
        //// Private -----------------------------------------------------------------
        //// USB Communication ///////////////////////////////////////////////////////
        this.TIMEOUT_MS = 5000;
        this.REPORT_SIZE = 64;
        this.VENDOR_ID = 0x25f8; // VID : Keypair
        this.PRODUCT_ID = 0x9002; // PID : ETRI DIM
        this.REP_ONE_BLOCK = 0xa5;
        this.REP_FIRST_BLOCK = 0xa1;
        this.REP_MIDDLE_BLOCK = 0x11;
        this.REP_LAST_BLOCK = 0x15;
        //// KseDim //////////////////////////////////////////////////////////////////
        this.KSE_POWER_OFF = 0;
        this.KSE_POWER_ON = 1;
        //// KCMVP ///////////////////////////////////////////////////////////////////
        this.KCMVP_DES = 0x20;
        this.KCMVP_TDES = 0x30;
        this.KCMVP_AES = 0x40;
        this.KCMVP_ARIA = 0x50;
        this.KCMVP_FAST_ARIA = 0x58;
        this.KCMVP_SHA = 0x60;
        this.KCMVP_HMAC_GEN = 0x70;
        this.KCMVP_HMAC_VERI = 0x78;
        this.KCMVP_ECDSA_SIGN = 0x80;
        this.KCMVP_ECDSA_VERI = 0x88;
        this.KCMVP_ECDH = 0x90;
        //////////////////////////////////////////////////////////////////////////////
        //// Properties //////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////
        //// Public ------------------------------------------------------------------
        this.gsKseLastErrorCode = KseDim.KSETLS_SUCCESS;
        this.gfEnableDebugPrint = false;
        //// Private -----------------------------------------------------------------
        //// Mutex ///////////////////////////////////////////////////////////////////
        this.gTrsvMutex = {
            isLocked: false,
        };
        this.gTlsMutex = {
            isLocked: false,
        };
        this.gaTlsMutex = new Array(KseDim.MAX_CHANNEL_COUNT).fill({
            isLocked: false,
        });
        this.gOpMutex = {
            isLocked: false,
        };
        this.gKcmvpMutex = {
            isLocked: false,
        };
        //// USB Communication ///////////////////////////////////////////////////////
        this.ghDevice = null;
        this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_NOT_FOUND;
        //// KseDim //////////////////////////////////////////////////////////////////
        this.gsKsePower = this.KSE_POWER_OFF;
        //// KSE /////////////////////////////////////////////////////////////////////
        this.gbVcType = KseDim.VC_DISABLED;
        //// KSETLS //////////////////////////////////////////////////////////////////
        this.gabEndpoint = new Array(KseDim.MAX_CHANNEL_COUNT);
        this.gaabNetData = new Array(KseDim.MAX_CHANNEL_COUNT).fill(new Array(KseDim.MAX_TRANSCEIVE_SIZE));
        this.gausNetDataLength = new Array(KseDim.MAX_CHANNEL_COUNT).fill(0);
        //////////////////////////////////////////////////////////////////////////////
        //// Methods /////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////////////
        /**---------------------------------------------------------------------------
         * Copies data from the source array to the destination array.
         *
         * @param src - (Input) source array
         * @param srcOff - (Input) source array offset
         * @param dst - (Output) destination array
         * @param dstOff - (Input) destination array offset
         * @param len - (Input) the length of data to copy
         * @returns `void`
         *
         * ```
         * Description:
         * - It does not handle the out of boundary exception.
         * ```
         * -------------------------------------------------------------------------*/
        this.ArrayCopy = function (src, srcOff, dst, dstOff, len) {
            for (var i = 0; i < len; i++) {
                dst[dstOff + i] = src[srcOff + i];
            }
        };
        /**---------------------------------------------------------------------------
         * Fills the array with the given value.
         *
         * @param arr - (Input) destination array
         * @param arrOff - (Input) array offset
         * @param value - (Input) value to fill with
         * @param len - (Input) the length of data to fill
         * @returns `void`
         *
         * ```
         * Description:
         * - It does not handle the out of boundary exception.
         * ```
         * -------------------------------------------------------------------------*/
        this.ArrayFill = function (arr, arrOff, value, len) {
            for (var i = 0; i < len; i++) {
                arr[arrOff + i] = value;
            }
        };
        /**---------------------------------------------------------------------------
         * Compares array a1 with a2.
         *
         * @param a1 - (Input) array to compare
         * @param a2 - (Input) array to compare with
         * @returns `true` if they are the same or `false`
         *
         * ```
         * Description:
         * - None.
         * ```
         * -------------------------------------------------------------------------*/
        this.ByteArrComp = function (a1, a2) {
            if (!a1 && !a2)
                return true;
            if ((!a1 && a2) || (a1 && !a2))
                return false;
            if (a1.length !== a2.length)
                return false;
            for (var i = 0; i < a1.length; i++) {
                if (a1[i] !== a2[i])
                    return false;
            }
            return true;
        };
        //// USB Communication ///////////////////////////////////////////////////////
        /**---------------------------------------------------------------------------
         * Transfers and receives data to and from KSE through USB.
         *
         * @param abSendData - (Input) data to send
         * @returns received data or null
         *
         * ```
         * Description:
         * - `ghDevice` is referenced.
         * - If an error occurs `gsTransceiveLastErrorCode` would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.Transceive = function (abSendData) { return __awaiter(_this, void 0, void 0, function () {
            var sSendLen, abOutReport, sLen, sOffset, abInReport, abOutBuffer, e_1, e_2, sRecvLen, abIoBuffer, e_3, e_4, abRecvData, e_5;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 30, , 32]);
                        return [4 /*yield*/, this.MutexLock(this.gTrsvMutex)];
                    case 1:
                        _a.sent();
                        if (!!this.ghDevice) return [3 /*break*/, 3];
                        this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_NOT_FOUND;
                        return [4 /*yield*/, this.MutexRelease(this.gTrsvMutex)];
                    case 2:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 3:
                        sSendLen = abSendData.length;
                        abOutReport = new Array(this.REPORT_SIZE).fill(0);
                        sLen = void 0;
                        sOffset = 0;
                        abInReport = new Array(this.REPORT_SIZE);
                        abOutBuffer = new Array(this.REPORT_SIZE + 1).fill(0);
                        _a.label = 4;
                    case 4:
                        if (!(sSendLen > 0)) return [3 /*break*/, 14];
                        if (abOutReport[0] === 0x00 && sSendLen <= 60)
                            abOutReport[0] = this.REP_ONE_BLOCK;
                        else if (abOutReport[0] === 0x00 && sSendLen > 60)
                            abOutReport[0] = this.REP_FIRST_BLOCK;
                        else if (abOutReport[0] !== 0x00 && sSendLen > 60)
                            abOutReport[0] = this.REP_MIDDLE_BLOCK;
                        else
                            abOutReport[0] = this.REP_LAST_BLOCK;
                        sLen = sSendLen > 60 ? 60 : sSendLen;
                        abOutReport[1] = 0x05;
                        abOutReport[2] = sOffset;
                        abOutReport[3] = sLen;
                        this.ArrayCopy(abSendData, sOffset * 60, abOutReport, 4, sLen);
                        sOffset++;
                        sSendLen -= sLen;
                        _a.label = 5;
                    case 5:
                        _a.trys.push([5, 6, , 8]);
                        this.ArrayFill(abOutBuffer, 0, 0, abOutBuffer.length);
                        this.ArrayCopy(abOutReport, 0, abOutBuffer, 1, this.REPORT_SIZE);
                        this.ghDevice.write(abOutBuffer);
                        return [3 /*break*/, 8];
                    case 6:
                        e_1 = _a.sent();
                        this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_USB_SEND_REPORT;
                        return [4 /*yield*/, this.MutexRelease(this.gTrsvMutex)];
                    case 7:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 8:
                        _a.trys.push([8, 9, , 11]);
                        abInReport = this.ghDevice.readSync();
                        return [3 /*break*/, 11];
                    case 9:
                        e_2 = _a.sent();
                        this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_USB_RECV_REPORT;
                        return [4 /*yield*/, this.MutexRelease(this.gTrsvMutex)];
                    case 10:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 11:
                        if (!(((abOutReport[0] === this.REP_ONE_BLOCK ||
                            abOutReport[0] === this.REP_LAST_BLOCK) &&
                            (abInReport[1] !== 0x06 || abInReport[2] !== 0x00)) ||
                            ((abOutReport[0] === this.REP_FIRST_BLOCK ||
                                abOutReport[0] === this.REP_MIDDLE_BLOCK) &&
                                (abInReport[0] !== abOutReport[0] ||
                                    abInReport[1] !== 0xfe ||
                                    abInReport[2] !== abOutReport[2] ||
                                    abInReport[3] !== abOutReport[3])))) return [3 /*break*/, 13];
                        this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP;
                        return [4 /*yield*/, this.MutexRelease(this.gTrsvMutex)];
                    case 12:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 13: return [3 /*break*/, 4];
                    case 14:
                        // Receive Data.
                        sOffset = 0;
                        sRecvLen = abInReport[3];
                        if (!(sRecvLen > KseDim.MAX_TRANSCEIVE_SIZE)) return [3 /*break*/, 16];
                        this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_RECV_BUF_OVERFLOW;
                        return [4 /*yield*/, this.MutexRelease(this.gTrsvMutex)];
                    case 15:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 16:
                        abIoBuffer = new Array(KseDim.MAX_TRANSCEIVE_SIZE).fill(0);
                        this.ArrayCopy(abInReport, 4, abIoBuffer, 0, sRecvLen);
                        if (!(abInReport[0] === this.REP_FIRST_BLOCK)) return [3 /*break*/, 28];
                        _a.label = 17;
                    case 17:
                        this.ArrayCopy(abInReport, 0, abOutReport, 0, 4);
                        abOutReport[1] = 0xfe;
                        _a.label = 18;
                    case 18:
                        _a.trys.push([18, 19, , 21]);
                        this.ArrayFill(abOutBuffer, 0, 0, abOutBuffer.length);
                        this.ArrayCopy(abOutReport, 0, abOutBuffer, 1, this.REPORT_SIZE);
                        this.ghDevice.write(abOutBuffer);
                        return [3 /*break*/, 21];
                    case 19:
                        e_3 = _a.sent();
                        this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_USB_SEND_REPORT;
                        return [4 /*yield*/, this.MutexRelease(this.gTrsvMutex)];
                    case 20:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 21:
                        _a.trys.push([21, 22, , 24]);
                        abInReport = this.ghDevice.readSync();
                        return [3 /*break*/, 24];
                    case 22:
                        e_4 = _a.sent();
                        this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_USB_RECV_REPORT;
                        return [4 /*yield*/, this.MutexRelease(this.gTrsvMutex)];
                    case 23:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 24:
                        sOffset = abInReport[2];
                        sLen = abInReport[3];
                        sRecvLen += sLen;
                        if (!(sRecvLen > KseDim.MAX_TRANSCEIVE_SIZE)) return [3 /*break*/, 26];
                        this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP;
                        return [4 /*yield*/, this.MutexRelease(this.gTrsvMutex)];
                    case 25:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 26:
                        this.ArrayCopy(abInReport, 4, abIoBuffer, sOffset * 60, sLen);
                        _a.label = 27;
                    case 27:
                        if (abInReport[0] === this.REP_MIDDLE_BLOCK) return [3 /*break*/, 17];
                        _a.label = 28;
                    case 28:
                        abRecvData = new Array(sRecvLen).fill(0);
                        this.ArrayCopy(abIoBuffer, 0, abRecvData, 0, sRecvLen);
                        return [4 /*yield*/, this.MutexRelease(this.gTrsvMutex)];
                    case 29:
                        _a.sent();
                        return [2 /*return*/, abRecvData];
                    case 30:
                        e_5 = _a.sent();
                        return [4 /*yield*/, this.MutexRelease(this.gTrsvMutex)];
                    case 31:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 32: return [2 /*return*/];
                }
            });
        }); };
        //// KSE100U /////////////////////////////////////////////////////////////////
        /**---------------------------------------------------------------------------
         * Finds KseDim devices from the input and returns the list of them.
         *
         * @param deviceList - (Input) USB HID device list
         * @returns KseDim device list or null
         *
         * ```
         * Description:
         * - `deviceList` would be an array of USB HID device instances.
         * ```
         * -------------------------------------------------------------------------*/
        this.GetKseDimDeviceList = function (deviceList) {
            var KseDimList = deviceList.filter(function (device) {
                return device.vendorId === _this.VENDOR_ID &&
                    device.productId === _this.PRODUCT_ID;
            });
            return KseDimList;
        };
        /**---------------------------------------------------------------------------
         * Powers off KSE.
         *
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * -  If an error occurs, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.PowerOff = function () { return __awaiter(_this, void 0, void 0, function () {
            var deviceList, kseDeviceList, abTxData, abRxData, sLen, sRv, e_6;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        // Check KSE power state.
                        // if (this.gsKsePower !== this.KSE_POWER_ON) {
                        //   if (this.ghDevice) this.ghDevice.close();
                        //   this.ghDevice = null;
                        //   this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                        //   return KseDim.KSE_FAIL;
                        // }
                        // Check KSE Device.
                        if (!this.ghDevice) {
                            deviceList = node_hid_1.default.devices();
                            if (!deviceList || deviceList.length === 0) {
                                this.gsKseLastErrorCode = KseDim.KSE_FAIL_USB_NO_DEVICES;
                                return [2 /*return*/, KseDim.KSE_FAIL];
                            }
                            kseDeviceList = this.GetKseDimDeviceList(deviceList);
                            if (!kseDeviceList || kseDeviceList.length === 0) {
                                this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_FOUND;
                                return [2 /*return*/, KseDim.KSE_FAIL];
                            }
                            // Connect DIM.
                            kseDeviceList.every(function (kseDevice) {
                                if (kseDevice.path) {
                                    try {
                                        _this.ghDevice = new node_hid_1.default.HID(kseDevice.path);
                                        return false;
                                    }
                                    catch (e) {
                                        return true;
                                    }
                                }
                            });
                            if (!this.ghDevice) {
                                this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_FOUND;
                                this.gsKsePower = this.KSE_POWER_OFF;
                                return [2 /*return*/, KseDim.KSE_SUCCESS];
                            }
                        }
                        abTxData = [0x0a, 0xff];
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 1:
                        abRxData = _a.sent();
                        if (!abRxData) {
                            if (this.ghDevice)
                                this.ghDevice.close();
                            this.ghDevice = null;
                            this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sLen = abRxData.length;
                        if (sLen !== 2) {
                            if (this.ghDevice)
                                this.ghDevice.close();
                            this.ghDevice = null;
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (sRv !== KseDim.KSE_SUCCESS) {
                            if (this.ghDevice)
                                this.ghDevice.close();
                            this.ghDevice = null;
                            this.gsKseLastErrorCode = sRv;
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        if (this.ghDevice)
                            this.ghDevice.close();
                        this.ghDevice = null;
                        this.gsKsePower = this.KSE_POWER_OFF;
                        return [2 /*return*/, sRv];
                    case 2:
                        e_6 = _a.sent();
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNKNOWN_ERR;
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 3: return [2 /*return*/];
                }
            });
        }); };
        //// Debug ///////////////////////////////////////////////////////////////////
        /**---------------------------------------------------------------------------
         * Prints network transceive data for debugging.
         *
         * @returns `void`
         *
         * ```
         * Description:
         * - 'bMode' should be one of the followings. < SENT(0) / RECV(1) >
         * ```
         * -------------------------------------------------------------------------*/
        this.DebugPrintNetTxRxData = function (bMode, abData) {
            if (_this.gfEnableDebugPrint !== true)
                return;
            if (bMode === KseDim.SENT)
                console.log("    + Sent Data:");
            else
                console.log("    + Received Data:");
            var i = 0;
            var message = "";
            for (i = 0; i < abData.length; i++) {
                message += ("0" + abData[i].toString(16)).substr(-2);
                if (i % 16 === 15 || i === abData.length - 1) {
                    console.log(message);
                    message = "";
                }
            }
            if (bMode === KseDim.SENT)
                console.log("    + Sent Data Length: ", abData.length);
            else
                console.log("    + Received Data Length: ", abData.length);
            console.log("");
        };
        /**---------------------------------------------------------------------------
         * Returns error string.
         *
         * @returns `error string`
         *
         * ```
         * Description:
         * - 'gsKseLastErrorCode' is referenced.
         * ```
         * -------------------------------------------------------------------------*/
        this.ErrStr = function () {
            var strKseErr;
            if (_this.gsKseLastErrorCode === KseDim.KSE_SUCCESS)
                strKseErr = "Success";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL)
                strKseErr = "Fail";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_WRONG_INPUT)
                strKseErr = "ICC wrong input";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_NOT_SUPPORTED)
                strKseErr = "ICC not supported";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_NOT_POWERED_ON)
                strKseErr = "ICC not powered on";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_ALREADY_POWERED_ON)
                strKseErr = "ICC already powered on";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_ATR)
                strKseErr = "ICC ATR error";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_PPS)
                strKseErr = "ICC PPS error";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_TX)
                strKseErr = "ICC Tx error";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_RX)
                strKseErr = "ICC Rx error";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_CHAINING)
                strKseErr = "ICC chaining error";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_APDU_FORMAT)
                strKseErr = "ICC wrong APDU format";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_UNKNOWN_CMD)
                strKseErr = "ICC unknown command";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_STATE)
                strKseErr = "ICC state error";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_CODE_VERIFY)
                strKseErr = "ICC code verification error";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_CRYPTO_VERIFY)
                strKseErr = "ICC crypto verification error";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_CERT_VERIFY)
                strKseErr = "ICC certificate verification error";
            else if (_this.gsKseLastErrorCode === KseDim.ICC_FAIL_FLASH)
                strKseErr = "ICC flash memory error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_WRONG_INPUT)
                strKseErr = "KSE wrong input";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_NOT_SUPPORTED)
                strKseErr = "KSE not supported";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_NOT_POWERED_ON)
                strKseErr = "KSE not powered on";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_ALREADY_POWERED_ON)
                strKseErr = "KSE already powered on";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_ATR)
                strKseErr = "KSE ATR error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_PPS)
                strKseErr = "KSE PPS error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_TX)
                strKseErr = "KSE Tx error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_RX)
                strKseErr = "KSE Rx error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_CHAINING)
                strKseErr = "KSE chaining error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_APDU_FORMAT)
                strKseErr = "KSE wrong APDU format";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_UNKNOWN_CMD)
                strKseErr = "KSE unknown command";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_STATE)
                strKseErr = "KSE state error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_CODE_VERIFY)
                strKseErr = "KSE code verification error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_CRYPTO_VERIFY)
                strKseErr = "KSE crypto verification error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_CERT_VERIFY)
                strKseErr = "KSE certificate verification error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_FLASH)
                strKseErr = "KSE flash memory error";
            else if ((_this.gsKseLastErrorCode & 0xff00) === 0x6f00)
                strKseErr = "[" + ("000" + _this.gsKseLastErrorCode.toString(16)).substr(-4) + "] CLIB error.";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_INIT)
                strKseErr = "USB initialization error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_NO_DEVICES)
                strKseErr = "No USB devices";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_DEVICE_OPEN)
                strKseErr = "USB device open error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_DETACH_KERNEL_DRIVER)
                strKseErr = "USB detach kernel driver error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_CLAIM_INTERFACE)
                strKseErr = "USB claim interface driver error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_SEND_REPORT)
                strKseErr = "USB send report error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_RECV_REPORT)
                strKseErr = "USB receive report error";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_NOT_FOUND)
                strKseErr = "KSE not found";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_UNEXPECTED_RESP)
                strKseErr = "KSE unexpected response";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN)
                strKseErr = "KSE unexpected response length";
            else if (_this.gsKseLastErrorCode === KseDim.KSE_FAIL_RECV_BUF_OVERFLOW)
                strKseErr = "USB receive buffer overflow";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_FRAGMENT_RECORD)
                strKseErr = "Fragment record";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_HELLO_VERIFY_REQUEST)
                strKseErr = "Hello verify requested";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_HANDSHAKE_IN_PROGRESS)
                strKseErr = "Handshake is not completed yet";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_HANDSHAKE_DONE)
                strKseErr = "Handshake done";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_CONFIG)
                strKseErr =
                    "Failed to get ip address! Please check your " +
                        "network configuration";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_SOCKET_FAILED)
                strKseErr = "Failed to open a socket";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_CONNECT_FAILED)
                strKseErr = "The connection to the given server:port failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_BIND_FAILED)
                strKseErr = "Binding of the socket failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_LISTEN_FAILED)
                strKseErr = "Could not listen on the socket";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_ACCEPT_FAILED)
                strKseErr = "Could not accept the incoming connection";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_RECV_FAILED)
                strKseErr = "Reading information from the socket failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_SEND_FAILED)
                strKseErr = "Sending information through the socket failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_CONN_RESET)
                strKseErr = "Connection was reset by peer";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_UNKNOWN_HOST)
                strKseErr = "Failed to get an IP address for the given " + "hostname";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_BUFFER_TOO_SMALL)
                strKseErr = "Buffer is too small to hold the data";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_INVALID_CONTEXT)
                strKseErr = "The context is invalid, eg because it was " + "free()ed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_POLL_FAILED)
                strKseErr = "Polling the net context failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_BAD_INPUT_DATA)
                strKseErr = "Input invalid";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_FEATURE_UNAVAILABLE)
                strKseErr = "The requested feature is not available";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_INPUT_DATA)
                strKseErr = "Bad input parameters to function";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_INVALID_MAC)
                strKseErr = "Verification of the message MAC failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_INVALID_RECORD)
                strKseErr = "An invalid SSL record was received";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CONN_EOF)
                strKseErr = "The connection indicated an EOF";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_UNKNOWN_CIPHER)
                strKseErr = "An unknown cipher was received";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_NO_CIPHER_CHOSEN)
                strKseErr =
                    "The server has no ciphersuites in common with " + "the client";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_NO_RNG)
                strKseErr = "No RNG was provided to the SSL module";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_NO_CLIENT_CERTIFICATE)
                strKseErr =
                    "No client certification received from the " +
                        "client, but required by the authentication mode";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CERTIFICATE_TOO_LARGE)
                strKseErr =
                    "Our own certificate(s) is/are too large to send " +
                        "in an SSL message";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CERTIFICATE_REQUIRED)
                strKseErr =
                    "The own certificate is not set, but needed by " + "the server";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_PRIVATE_KEY_REQUIRED)
                strKseErr =
                    "The own private key or pre-shared key is not " + "set, but needed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CA_CHAIN_REQUIRED)
                strKseErr = "No CA Chain is set, but required to operate";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_UNEXPECTED_MESSAGE)
                strKseErr = "An unexpected message was received from our peer";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_FATAL_ALERT_MESSAGE)
                strKseErr = "A fatal alert message was received from our peer";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_PEER_VERIFY_FAILED)
                strKseErr = "Verification of our peer failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_PEER_CLOSE_NOTIFY)
                strKseErr =
                    "The peer notified us that the connection is " + "going to be closed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_HS_CLIENT_HELLO)
                strKseErr = "Processing of the ClientHello handshake message " + "failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_HS_SERVER_HELLO)
                strKseErr = "Processing of the ServerHello handshake message " + "failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_HS_CERTIFICATE)
                strKseErr = "Processing of the Certificate handshake message " + "failed";
            else if (_this.gsKseLastErrorCode ===
                KseDim.KSETLS_ERR_TLS_BAD_HS_CERTIFICATE_REQUEST)
                strKseErr =
                    "Processing of the CertificateRequest handshake " + "message failed";
            else if (_this.gsKseLastErrorCode ===
                KseDim.KSETLS_ERR_TLS_BAD_HS_SERVER_KEY_EXCHANGE)
                strKseErr =
                    "Processing of the ServerKeyExchange handshake " + "message failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_HS_SERVER_HELLO_DONE)
                strKseErr =
                    "Processing of the ServerHelloDone handshake " + "message failed";
            else if (_this.gsKseLastErrorCode ===
                KseDim.KSETLS_ERR_TLS_BAD_HS_CLIENT_KEY_EXCHANGE)
                strKseErr =
                    "Processing of the ClientKeyExchange handshake " + "message failed";
            else if (_this.gsKseLastErrorCode ===
                KseDim.KSETLS_ERR_TLS_BAD_HS_CLIENT_KEY_EXCHANGE_RP)
                strKseErr =
                    "Processing of the ClientKeyExchange handshake " +
                        "message failed in DHM / ECDH Read Public";
            else if (_this.gsKseLastErrorCode ===
                KseDim.KSETLS_ERR_TLS_BAD_HS_CLIENT_KEY_EXCHANGE_CS)
                strKseErr =
                    "Processing of the ClientKeyExchange handshake " +
                        "message failed in DHM / ECDH Calculate Secret";
            else if (_this.gsKseLastErrorCode ===
                KseDim.KSETLS_ERR_TLS_BAD_HS_CERTIFICATE_VERIFY)
                strKseErr =
                    "Processing of the CertificateVerify handshake " + "message failed";
            else if (_this.gsKseLastErrorCode ===
                KseDim.KSETLS_ERR_TLS_BAD_HS_CHANGE_CIPHER_SPEC)
                strKseErr =
                    "Processing of the ChangeCipherSpec handshake " + "message failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_HS_FINISHED)
                strKseErr = "Processing of the Finished handshake message " + "failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_ALLOC_FAILED)
                strKseErr = "Memory allocation failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_HW_ACCEL_FAILED)
                strKseErr = "Hardware acceleration function returned with " + "error";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_HW_ACCEL_FALLTHROUGH)
                strKseErr =
                    "Hardware acceleration function skipped / left " + "alone data";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_COMPRESSION_FAILED)
                strKseErr = "Processing of the compression / decompression " + "failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_HS_PROTOCOL_VERSION)
                strKseErr = "Handshake protocol not within min/max boundaries";
            else if (_this.gsKseLastErrorCode ===
                KseDim.KSETLS_ERR_TLS_BAD_HS_NEW_SESSION_TICKET)
                strKseErr =
                    "Processing of the NewSessionTicket handshake " + "message failed";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_SESSION_TICKET_EXPIRED)
                strKseErr = "Session ticket has expired";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_PK_TYPE_MISMATCH)
                strKseErr =
                    "Public key type mismatch (eg, asked for RSA key " +
                        "exchange and presented EC key)";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_UNKNOWN_IDENTITY)
                strKseErr = "Unknown identity received (eg, PSK identity)";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_INTERNAL_ERROR)
                strKseErr =
                    "Internal error (eg, unexpected failure in " + "lower-level module)";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_COUNTER_WRAPPING)
                strKseErr = "A counter would wrap (eg, too many messages " + "exchanged)";
            else if (_this.gsKseLastErrorCode ===
                KseDim.KSETLS_ERR_TLS_WAITING_SERVER_HELLO_RENEGO)
                strKseErr = "Unexpected message at ServerHello in " + "renegotiation";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_HELLO_VERIFY_REQUIRED)
                strKseErr = "DTLS client must retry for hello verification";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BUFFER_TOO_SMALL)
                strKseErr = "A buffer is too small to receive or write a " + "message";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_NO_USABLE_CIPHERSUITE)
                strKseErr =
                    "None of the common ciphersuites is usable (eg, " +
                        "no suitable certificate, see debug messages)";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_WANT_READ)
                strKseErr =
                    "No data of requested type currently available " +
                        "on underlying transport";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_WANT_WRITE)
                strKseErr = "Connection requires a write call";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_TIMEOUT)
                strKseErr = "The operation timed out";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CLIENT_RECONNECT)
                strKseErr = "The client initiated a reconnect from the same " + "port";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_UNEXPECTED_RECORD)
                strKseErr = "Record header looks valid but is not expected";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_NON_FATAL)
                strKseErr = "The alert message received indicates a " + "non-fatal error";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_INVALID_VERIFY_HASH)
                strKseErr = "Couldn't set the hash for verifying " + "CertificateVerify";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CONTINUE_PROCESSING)
                strKseErr =
                    "Internal-only message signaling that further " +
                        "message-processing should be done";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_ASYNC_IN_PROGRESS)
                strKseErr = "The asynchronous operation is not completed yet";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_EARLY_MESSAGE)
                strKseErr =
                    "Internal-only message signaling that a message " + "arrived early";
            else if (_this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CRYPTO_IN_PROGRESS)
                strKseErr = "A cryptographic operation failure in progress.";
            else {
                strKseErr = "[" + ("000" + _this.gsKseLastErrorCode.toString(16)).substr(-4) + "] KSE unknown error.";
            }
            return strKseErr;
        };
        /**---------------------------------------------------------------------------
         * Prints error string for debugging.
         *
         * @returns `void`
         *
         * ```
         * Description:
         * - 'gsKseLastErrorCode' would be referenced.
         * ```
         * -------------------------------------------------------------------------*/
        this.DebugPrintErrStr = function (strErrFunc) {
            if (_this.gfEnableDebugPrint !== true)
                return;
            console.log(strErrFunc + " : " + _this.ErrStr());
        };
        //// KCMVP ///////////////////////////////////////////////////////////////////
        /**---------------------------------------------------------------------------
         * < DES / TDES / AES / ARIA / HMAC-SHA2-256 / ECDSA-P256 / ECDH-P256 >
         * Puts the key in the KSE nonvolatile memory.
         *
         * @param bKeyType         - (Input) key type
         * @param usKeyIndex       - (Input) key index
         * @param abKey            - (Input) key data
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * - 'bKeyType' should be one of belows.
         * < KCMVP_DES_KEY('20') / KCMVP_TDES_KEY('30') /
         * KCMVP_AES128_KEY('40') / KCMVP_AES192_KEY('41') / KCMVP_AES256_KEY('42') /
         * KCMVP_ARIA128_KEY('50') / KCMVP_ARIA192_KEY('51') /
         * KCMVP_ARIA256_KEY('52') / KCMVP_HMAC_KEY('70') /
         * KCMVP_ECDSA_PRI_KEY('81') / KCMVP_ECDSA_PUB_KEY('82') /
         * KCMVP_ECDH_PRI_KEY('91') / KCMVP_ECDH_PUB_KEY('92') >
         * - 'usKeyIndex' should be 0 ~ 7.
         * -  The area of 'bKeyType' and 'usKeyIndex' should be empty.
         * - 'abKey' array size should be one of belows according to 'bKeyType'.
         * < 8  (KCMVP_DES_KEY) / 16 (KCMVP_AES128_KEY / KCMVP_ARIA128_KEY) /
         * 24 (KCMVP_TDES_KEY / KCMVP_AES192_KEY / KCMVP_ARIA192_KEY) /
         * 32 (KCMVP_AES256_KEY / KCMVP_ARIA256_KEY / KCMVP_ECDSA_PRI_KEY /
         * KCMVP_ECDH_PRI_KEY) / 64 (KCMVP_ECDSA_PUB_KEY / KCMVP_ECDH_PUB_KEY) /
         * 0 ~ 255 (KCMVP_HMAC_KEY) >
         * -  This method can be used only in the 'ISSUED User' state.
         * -  If an error occurs, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KcmvpPutKey = function (bKeyType, usKeyIndex, abKey) { return __awaiter(_this, void 0, void 0, function () {
            var usKeySize, abTxData, abRxData, usLen, sRv;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.MutexLock(this.gKcmvpMutex)];
                    case 1:
                        _a.sent();
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        if (!(this.gsKsePower !== this.KSE_POWER_ON)) return [3 /*break*/, 3];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 2:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 3:
                        if (!((bKeyType !== KseDim.KCMVP_DES_KEY &&
                            bKeyType !== KseDim.KCMVP_TDES_KEY &&
                            bKeyType !== KseDim.KCMVP_AES128_KEY &&
                            bKeyType !== KseDim.KCMVP_AES192_KEY &&
                            bKeyType !== KseDim.KCMVP_AES256_KEY &&
                            bKeyType !== KseDim.KCMVP_ARIA128_KEY &&
                            bKeyType !== KseDim.KCMVP_ARIA192_KEY &&
                            bKeyType !== KseDim.KCMVP_ARIA256_KEY &&
                            bKeyType !== KseDim.KCMVP_HMAC_KEY &&
                            bKeyType !== KseDim.KCMVP_ECDSA_PRI_KEY &&
                            bKeyType !== KseDim.KCMVP_ECDSA_PUB_KEY &&
                            bKeyType !== KseDim.KCMVP_ECDH_PRI_KEY &&
                            bKeyType !== KseDim.KCMVP_ECDH_PUB_KEY) ||
                            usKeyIndex >= KseDim.MAX_KCMVP_KEY_COUNT ||
                            abKey === null ||
                            (bKeyType === KseDim.KCMVP_DES_KEY && abKey.length !== 8) ||
                            ((bKeyType === KseDim.KCMVP_AES128_KEY ||
                                bKeyType === KseDim.KCMVP_ARIA128_KEY) &&
                                abKey.length !== 16) ||
                            ((bKeyType === KseDim.KCMVP_TDES_KEY ||
                                bKeyType === KseDim.KCMVP_AES192_KEY ||
                                bKeyType === KseDim.KCMVP_ARIA192_KEY) &&
                                abKey.length !== 24) ||
                            ((bKeyType === KseDim.KCMVP_AES256_KEY ||
                                bKeyType === KseDim.KCMVP_ARIA256_KEY ||
                                bKeyType === KseDim.KCMVP_ECDSA_PRI_KEY ||
                                bKeyType === KseDim.KCMVP_ECDH_PRI_KEY) &&
                                abKey.length !== 32) ||
                            ((bKeyType === KseDim.KCMVP_ECDSA_PUB_KEY ||
                                bKeyType === KseDim.KCMVP_ECDH_PUB_KEY) &&
                                abKey.length !== 64) ||
                            (bKeyType === KseDim.KCMVP_HMAC_KEY && abKey.length > 255))) return [3 /*break*/, 5];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 4:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 5:
                        usKeySize = abKey.length;
                        if (bKeyType !== KseDim.KCMVP_HMAC_KEY)
                            abTxData = new Array(usKeySize + 5);
                        else
                            abTxData = new Array(usKeySize + 7);
                        abTxData[0] = 0x02;
                        abTxData[1] = 0x01;
                        abTxData[2] = bKeyType;
                        abTxData[3] = (usKeyIndex >> 8) & 0xff;
                        abTxData[4] = usKeyIndex & 0xff;
                        if (bKeyType !== KseDim.KCMVP_HMAC_KEY)
                            this.ArrayCopy(abKey, 0, abTxData, 5, usKeySize);
                        else {
                            abTxData[5] = (usKeySize >> 8) & 0xff;
                            abTxData[6] = usKeySize & 0xff;
                            this.ArrayCopy(abKey, 0, abTxData, 7, usKeySize);
                        }
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 6:
                        abRxData = _a.sent();
                        if (!!abRxData) return [3 /*break*/, 8];
                        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 7:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 8:
                        usLen = abRxData.length;
                        if (!(usLen !== 2)) return [3 /*break*/, 10];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 9:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 10:
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (!(sRv !== KseDim.KSE_SUCCESS)) return [3 /*break*/, 12];
                        this.gsKseLastErrorCode = sRv;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 11:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 12: return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 13:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * < DES / TDES / AES / ARIA / HMAC-SHA2-256 / ECDSA-P256 / ECDH-P256 >
         * Erases the key in the KSE nonvolatile memory.
         *
         * @param bKeyType         - (Input) key type
         * @param usKeyIndex       - (Input) key index
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * - 'bKeyType' should be one of belows.
         * < KCMVP_DES_KEY('20') / KCMVP_TDES_KEY('30') / KCMVP_AES128_KEY('40') /
         * KCMVP_AES192_KEY('41') / KCMVP_AES256_KEY('42') / KCMVP_ARIA128_KEY('50') /
         * KCMVP_ARIA192_KEY('51') / KCMVP_ARIA256_KEY('52') / KCMVP_HMAC_KEY('70') /
         * KCMVP_ECDSA_PRI_KEY('81') / KCMVP_ECDSA_PUB_KEY('82') /
         * KCMVP_ECDH_PRI_KEY('91') / KCMVP_ECDH_PUB_KEY('92') >
         * -  'usKeyIndex' should be 0 ~ 7.
         * -  This method can be used only in the 'ISSUED User' state.
         * -  If an error occurs, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KcmvpEraseKey = function (bKeyType, usKeyIndex) { return __awaiter(_this, void 0, void 0, function () {
            var abTxData, abRxData, usLen, sRv;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.MutexLock(this.gKcmvpMutex)];
                    case 1:
                        _a.sent();
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        if (!(this.gsKsePower !== this.KSE_POWER_ON)) return [3 /*break*/, 3];
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 2:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL_NOT_POWERED_ON];
                    case 3:
                        if (!((bKeyType !== KseDim.KCMVP_DES_KEY &&
                            bKeyType !== KseDim.KCMVP_TDES_KEY &&
                            bKeyType !== KseDim.KCMVP_AES128_KEY &&
                            bKeyType !== KseDim.KCMVP_AES192_KEY &&
                            bKeyType !== KseDim.KCMVP_AES256_KEY &&
                            bKeyType !== KseDim.KCMVP_ARIA128_KEY &&
                            bKeyType !== KseDim.KCMVP_ARIA192_KEY &&
                            bKeyType !== KseDim.KCMVP_ARIA256_KEY &&
                            bKeyType !== KseDim.KCMVP_HMAC_KEY &&
                            bKeyType !== KseDim.KCMVP_ECDSA_PRI_KEY &&
                            bKeyType !== KseDim.KCMVP_ECDSA_PUB_KEY &&
                            bKeyType !== KseDim.KCMVP_ECDH_PRI_KEY &&
                            bKeyType !== KseDim.KCMVP_ECDH_PUB_KEY) ||
                            usKeyIndex >= KseDim.MAX_KCMVP_KEY_COUNT)) return [3 /*break*/, 5];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 4:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 5:
                        abTxData = new Array(5);
                        abTxData[0] = 0x02;
                        abTxData[1] = 0x03;
                        abTxData[2] = bKeyType;
                        abTxData[3] = (usKeyIndex >> 8) & 0xff;
                        abTxData[4] = usKeyIndex & 0xff;
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 6:
                        abRxData = _a.sent();
                        if (!!abRxData) return [3 /*break*/, 8];
                        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 7:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 8:
                        usLen = abRxData.length;
                        if (!(usLen !== 2)) return [3 /*break*/, 10];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 9:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 10:
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (!(sRv !== KseDim.KSE_SUCCESS)) return [3 /*break*/, 12];
                        this.gsKseLastErrorCode = sRv;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 11:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 12: return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 13:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * < SHA2-256 / HMAC-SHA2-256 / ECDSA-P256 >
         * Hash, MAC, Signature, and Verification.
         *
         * @param abInput      - (Input) input data
         * @param abMessage    - (Input) message to sign
         * @param usKeyIndex   - (Input) key index
         * @param bAlg         - (Input) cryptographic operation algorithm
         * @returns `byte array` or `null`
         *
         * ```
         * Description:
         * -  This method is an internal method for SHA2-256 / HMAC-SHA2-256 /
         * ECDSA-P256.
         * -  'usKeyIndex' should be 0 ~ 7.
         * -  'bAlg' should be one of belows.
         * < KCMVP_SHA('60') / KCMVP_HMAC_GEN('70') / KCMVP_HMAC_VERI('78') /
         * KCMVP_ECDSA_SIGN('80') / KCMVP_ECDSA_VERI('88') >
         * -  If 'bAlg' is KCMVP_SHA, 'abInput' is not used.
         * -  If 'bAlg' is KCMVP_HMAC_GEN, 'abInput' is not used.
         * -  If 'bAlg' is KCMVP_HMAC_VERI, 'abInput' is input 32-byte HMAC.
         * -  If 'bAlg' is KCMVP_ECDSA_SIGN, 'abInput' is not used.
         * -  If 'bAlg' is KCMVP_ECDSA_VERI, 'abInput' is input 64-byte R || S.
         * -  This method can be used only in the 'ISSUED User' state.
         * -  If an error occurs, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KcmvpHashDsa = function (bCh, abInput, abMessage, usKeyIndex, bAlg) { return __awaiter(_this, void 0, void 0, function () {
            var bKeyIndexMask, ulMessageSize, i, sRv, usSize, usLen, abTxData, abRxData, ulMessageOffset, abOutput;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.MutexLock(this.gKcmvpMutex)];
                    case 1:
                        _a.sent();
                        if (!(this.gsKsePower !== this.KSE_POWER_ON)) return [3 /*break*/, 3];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 2:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 3:
                        bKeyIndexMask = (usKeyIndex & 0x8000) >> 8;
                        usKeyIndex &= 0x7fff;
                        if (abMessage === null)
                            abMessage = new Array(0);
                        if (!(bCh >= KseDim.MAX_CHANNEL_COUNT ||
                            (bAlg === this.KCMVP_HMAC_VERI &&
                                (abInput === null || abInput.length !== 32)) ||
                            (bAlg === this.KCMVP_ECDSA_VERI &&
                                (abInput === null || abInput.length !== 64)) ||
                            ((bAlg === this.KCMVP_HMAC_GEN || bAlg === this.KCMVP_HMAC_VERI) &&
                                (bKeyIndexMask === 0x80 || usKeyIndex >= KseDim.MAX_KCMVP_KEY_COUNT)) ||
                            ((bAlg === this.KCMVP_ECDSA_SIGN || bAlg === this.KCMVP_ECDSA_VERI) &&
                                ((bKeyIndexMask === 0x00 && usKeyIndex >= KseDim.MAX_KCMVP_KEY_COUNT) ||
                                    (bKeyIndexMask === 0x80 && usKeyIndex >= KseDim.MAX_CERT_KEY_COUNT))))) return [3 /*break*/, 5];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 4:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 5:
                        ulMessageSize = abMessage.length;
                        if (!(ulMessageSize <= KseDim.MAX_IO_DATA_SIZE)) return [3 /*break*/, 7];
                        if (bAlg === this.KCMVP_SHA)
                            usSize = 4;
                        else if (bAlg === this.KCMVP_HMAC_VERI)
                            usSize = 38;
                        else if (bAlg === this.KCMVP_ECDSA_SIGN)
                            usSize = 7;
                        else if (bAlg === this.KCMVP_ECDSA_VERI)
                            usSize = 71;
                        else
                            usSize = 6;
                        abTxData = new Array(ulMessageSize + usSize);
                        abTxData[0] = 0x02;
                        abTxData[1] = (bAlg | 0x04) & 0xff;
                        i = 2;
                        if (bAlg === this.KCMVP_ECDSA_SIGN)
                            abTxData[i++] = (0x81 ^ bKeyIndexMask) & 0xff;
                        else if (bAlg === this.KCMVP_ECDSA_VERI)
                            abTxData[i++] = (0x82 ^ bKeyIndexMask) & 0xff;
                        if (bAlg !== this.KCMVP_SHA) {
                            abTxData[i++] = (usKeyIndex >> 8) & 0xff;
                            abTxData[i++] = usKeyIndex & 0xff;
                        }
                        abTxData[i++] = (ulMessageSize >> 8) & 0xff;
                        abTxData[i++] = ulMessageSize & 0xff;
                        this.ArrayCopy(abMessage, 0, abTxData, i, ulMessageSize);
                        i += ulMessageSize;
                        if (bAlg === this.KCMVP_HMAC_VERI)
                            this.ArrayCopy(abInput, 0, abTxData, i, 32);
                        else if (bAlg === this.KCMVP_ECDSA_VERI)
                            this.ArrayCopy(abInput, 0, abTxData, i, 64);
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 6:
                        abRxData = _a.sent();
                        return [3 /*break*/, 25];
                    case 7:
                        // Hash, MAC, Signature, Verification - Begin.
                        if (bAlg === this.KCMVP_HMAC_GEN || bAlg === this.KCMVP_HMAC_VERI)
                            usSize = 7;
                        else
                            usSize = 5;
                        abTxData = new Array(KseDim.MAX_IO_DATA_SIZE + usSize);
                        abTxData[0] = 0x02;
                        abTxData[1] = (bAlg | 0x05) & 0xff;
                        abTxData[2] = bCh;
                        i = 3;
                        if (bAlg === this.KCMVP_HMAC_GEN || bAlg === this.KCMVP_HMAC_VERI) {
                            abTxData[i++] = (usKeyIndex >> 8) & 0xff;
                            abTxData[i++] = usKeyIndex & 0xff;
                        }
                        abTxData[i++] = (KseDim.MAX_IO_DATA_SIZE >> 8) & 0xff;
                        abTxData[i++] = KseDim.MAX_IO_DATA_SIZE & 0xff;
                        this.ArrayCopy(abMessage, 0, abTxData, i, KseDim.MAX_IO_DATA_SIZE);
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 8:
                        abRxData = _a.sent();
                        if (!(abRxData === null)) return [3 /*break*/, 10];
                        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 9:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 10:
                        usLen = abRxData.length;
                        if (!(usLen !== 2)) return [3 /*break*/, 12];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 11:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 12:
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (!(sRv !== KseDim.KSE_SUCCESS)) return [3 /*break*/, 14];
                        this.gsKseLastErrorCode = sRv;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 13:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 14:
                        ulMessageOffset = KseDim.MAX_IO_DATA_SIZE;
                        ulMessageSize -= KseDim.MAX_IO_DATA_SIZE;
                        _a.label = 15;
                    case 15:
                        if (!(ulMessageSize > KseDim.MAX_IO_DATA_SIZE)) return [3 /*break*/, 23];
                        abTxData = new Array(KseDim.MAX_IO_DATA_SIZE + 5);
                        abTxData[0] = 0x02;
                        abTxData[1] = (bAlg | 0x06) & 0xff;
                        abTxData[2] = bCh;
                        abTxData[3] = (KseDim.MAX_IO_DATA_SIZE >> 8) & 0xff;
                        abTxData[4] = KseDim.MAX_IO_DATA_SIZE & 0xff;
                        this.ArrayCopy(abMessage, ulMessageOffset, abTxData, 5, KseDim.MAX_IO_DATA_SIZE);
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 16:
                        abRxData = _a.sent();
                        if (!(abRxData === null)) return [3 /*break*/, 18];
                        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 17:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 18:
                        usLen = abRxData.length;
                        if (!(usLen !== 2)) return [3 /*break*/, 20];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 19:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 20:
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (!(sRv !== KseDim.KSE_SUCCESS)) return [3 /*break*/, 22];
                        this.gsKseLastErrorCode = sRv;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 21:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 22:
                        ulMessageOffset += KseDim.MAX_IO_DATA_SIZE;
                        ulMessageSize -= KseDim.MAX_IO_DATA_SIZE;
                        return [3 /*break*/, 15];
                    case 23:
                        // Hash, MAC, Signature, Verification - End.
                        if (bAlg === this.KCMVP_ECDSA_SIGN)
                            usSize = 8;
                        else if (bAlg === this.KCMVP_ECDSA_VERI)
                            usSize = 72;
                        else if (bAlg === this.KCMVP_HMAC_VERI)
                            usSize = 37;
                        else
                            usSize = 5;
                        abTxData = new Array(ulMessageSize + usSize);
                        abTxData[0] = 0x02;
                        abTxData[1] = (bAlg | 0x07) & 0xff;
                        abTxData[2] = bCh;
                        i = 3;
                        if (bAlg === this.KCMVP_ECDSA_SIGN)
                            abTxData[i++] = (0x81 ^ bKeyIndexMask) & 0xff;
                        else if (bAlg === this.KCMVP_ECDSA_VERI)
                            abTxData[i++] = (0x82 ^ bKeyIndexMask) & 0xff;
                        if (bAlg === this.KCMVP_ECDSA_SIGN || bAlg === this.KCMVP_ECDSA_VERI) {
                            abTxData[i++] = (usKeyIndex >> 8) & 0xff;
                            abTxData[i++] = usKeyIndex & 0xff;
                        }
                        abTxData[i++] = (ulMessageSize >> 8) & 0xff;
                        abTxData[i++] = ulMessageSize & 0xff;
                        this.ArrayCopy(abMessage, ulMessageOffset, abTxData, i, ulMessageSize);
                        i += ulMessageSize;
                        if (bAlg === this.KCMVP_HMAC_VERI)
                            this.ArrayCopy(abInput, 0, abTxData, i, 32);
                        else if (bAlg === this.KCMVP_ECDSA_VERI)
                            this.ArrayCopy(abInput, 0, abTxData, i, 64);
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 24:
                        abRxData = _a.sent();
                        _a.label = 25;
                    case 25:
                        if (!(abRxData === null)) return [3 /*break*/, 27];
                        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 26:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 27:
                        usLen = abRxData.length;
                        if (!(usLen < 2)) return [3 /*break*/, 29];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 28:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 29:
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (!((sRv === KseDim.KSE_SUCCESS &&
                            (((bAlg === this.KCMVP_SHA || bAlg === this.KCMVP_HMAC_GEN) &&
                                usLen !== 34) ||
                                (bAlg === this.KCMVP_ECDSA_SIGN && usLen !== 66))) ||
                            ((sRv !== KseDim.KSE_SUCCESS ||
                                bAlg === this.KCMVP_HMAC_VERI ||
                                bAlg === this.KCMVP_ECDSA_VERI) &&
                                usLen !== 2))) return [3 /*break*/, 31];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 30:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 31:
                        if (!(sRv !== KseDim.KSE_SUCCESS)) return [3 /*break*/, 33];
                        this.gsKseLastErrorCode = sRv;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 32:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 33:
                        abOutput = null;
                        if (bAlg === this.KCMVP_SHA || bAlg === this.KCMVP_HMAC_GEN) {
                            abOutput = new Array(32);
                            this.ArrayCopy(abRxData, 2, abOutput, 0, 32);
                        }
                        else if (bAlg === this.KCMVP_ECDSA_SIGN) {
                            abOutput = new Array(64);
                            this.ArrayCopy(abRxData, 2, abOutput, 0, 64);
                        }
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 34:
                        _a.sent();
                        return [2 /*return*/, abOutput];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * < ECDSA-P256 > Signature.
         *
         * @param bCh          - (Input) channel
         * @param abMessage    - (Input) message to sign
         * @param usKeyIndex   - (Input) key index
         * @returns `byte array` or `null`
         *
         * ```
         * Description:
         * - 'bCh' should be 0 ~ 5.
         * - 'usKeyIndex' should be 0 + KCMVP_KEY_INDEX('0000')
              ~ 63 + KCMVP_KEY_INDEX('0000') for KCMVP private
              key, 0 + CERT_KEY_INDEX('8000') ~ 1023 +
              CERT_KEY_INDEX('8000') for CERT private key.
         * -  This method can be used only in the 'ISSUED User' state.
         * -  If error, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KcmvpEcdsaSign = function (bCh, abMessage, usKeyIndex) { return __awaiter(_this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.KcmvpHashDsa(bCh, null, abMessage, usKeyIndex, this.KCMVP_ECDSA_SIGN)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * < ECDSA-P256 > Verification.
         *
         * @param bCh          - (Input) channel
         * @param abMessage    - (Input) message
         * @param abRs         - (Input) signature to verify
         * @param usKeyIndex   - (Input) key index
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description: - 'bCh' should be 0 ~ 5.
         * - 'abRs' should be 64-byte array.
         * - 'usKeyIndex' should be 0 + KCMVP_KEY_INDEX('0000')
         *    ~ 63 + KCMVP_KEY_INDEX('0000') for KCMVP private key,
         *    0 + CERT_KEY_INDEX('8000') ~ 1023 + CERT_KEY_INDEX('8000') for CERT
         *    private key.
         * -  This method can be used only in the 'ISSUED User' state.
         * -  If error, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KcmvpEcdsaVerify = function (bCh, abMessage, abRs, usKeyIndex) { return __awaiter(_this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.MutexLock(this.gOpMutex)];
                    case 1:
                        _a.sent();
                        return [4 /*yield*/, this.KcmvpHashDsa(bCh, abRs, abMessage, usKeyIndex, this.KCMVP_ECDSA_VERI)];
                    case 2:
                        _a.sent();
                        if (!(this.gsKseLastErrorCode !== KseDim.KSE_SUCCESS)) return [3 /*break*/, 4];
                        return [4 /*yield*/, this.MutexRelease(this.gOpMutex)];
                    case 3:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 4: return [4 /*yield*/, this.MutexRelease(this.gOpMutex)];
                    case 5:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
            });
        }); };
        //// TCP Communication ///////////////////////////////////////////////////////
        /**---------------------------------------------------------------------------
         * <TLS> Receives data.
         *
         * @param iDataType         - (Input) data type
         * @param abData            - (Output) received data
         * @param bCh               - (Input) channel
         * @param iTimeout          - (Input) timeout
         * @returns `Number of received bytes(>=0)` or `KSETLS_ERR_NET_...(<0)`
         *
         * ```
         * Description:
         * - 'iDataType' should be KSETLS_DATA_HANDSHAKE | KSETLS_DATA_ENCRYPT
         *   KSETLS_DATA_CLOSE | KSETLS_DATA_WARNING
         * - 'bCh' should be 0 ~ 5.
         * - 'iTimeout' should be in milliseconds.
         * -  This method can be modified by the user.
         * ```
         * -------------------------------------------------------------------------*/
        this.TlsRecv = function (iDataType, abData, clientId, bCh, iTimeout) { return __awaiter(_this, void 0, void 0, function () {
            var sInLen, abRecv, e_7, abRecvData;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        sInLen = 0;
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, this.tlsReadHanldler.read(iDataType, clientId, bCh, iTimeout)];
                    case 2:
                        abRecv = _a.sent();
                        if (!abRecv) {
                            sInLen = KseDim.KSETLS_ERR_NET_RECV_FAILED;
                        }
                        else {
                            sInLen = abRecv.length;
                            this.ArrayCopy(abRecv, 0, abData, 0, sInLen);
                        }
                        return [3 /*break*/, 4];
                    case 3:
                        e_7 = _a.sent();
                        sInLen = KseDim.KSETLS_ERR_NET_RECV_FAILED;
                        return [3 /*break*/, 4];
                    case 4:
                        if (this.gfEnableDebugPrint === true && sInLen >= 0) {
                            abRecvData = new Array(sInLen);
                            this.ArrayCopy(abData, 0, abRecvData, 0, sInLen);
                            this.DebugPrintNetTxRxData(KseDim.RECV, abRecvData);
                        }
                        return [2 /*return*/, sInLen];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * <TLS> Sends data.
         *
         * @param iDataType         - (Output) data type
         * @param clientId          - (Input) client id
         * @param bCh               - (Input) channel
         * @param abData            - (Output) data to send
         * @returns `Number of sent bytes(>=0)` or `KSETLS_ERR_NET_...(<0)`
         *
         * ```
         * Description:
         * - 'iDataType' should be KSETLS_DATA_HANDSHAKE | KSETLS_DATA_ENCRYPT
         *   KSETLS_DATA_CLOSE | KSETLS_DATA_WARNING
         * - 'bCh' should be 0 ~ 5.
         * -  This method can be modified by the user.
         * ```
         * -------------------------------------------------------------------------*/
        this.TlsSend = function (iDataType, clientId, bCh, abData) { return __awaiter(_this, void 0, void 0, function () {
            var sOutLen, e_8;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        sOutLen = -1;
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, this.tlsWriteHanldler.write(iDataType, clientId, bCh, abData)];
                    case 2:
                        sOutLen = _a.sent();
                        if (sOutLen < 0)
                            sOutLen = KseDim.KSETLS_ERR_NET_SEND_FAILED;
                        return [3 /*break*/, 4];
                    case 3:
                        e_8 = _a.sent();
                        sOutLen = KseDim.KSETLS_ERR_NET_SEND_FAILED;
                        return [3 /*break*/, 4];
                    case 4:
                        if (this.gfEnableDebugPrint === true && sOutLen >= 0)
                            this.DebugPrintNetTxRxData(KseDim.SENT, abData);
                        return [2 /*return*/, sOutLen];
                }
            });
        }); };
        //// kseTLS ////////////////////////////////////////////////////////////////
        /**---------------------------------------------------------------------------
         * <kseTLS> Opens a kseTLS channel.
         *
         * @param bCh                   - (Input) channel
         * @param bMode                 - (Input) TLS or DTLS mode
         * @param bEndpoint             - (Input) client or server endpoint
         * @param usKseDevCertIndex     - (Input) development certificate index
         * @param usKseSubCaCertIndex   - (Input) sub CA certificate index
         * @param usKseRootCaCertIndex  - (Input) root CA certificate index
         * @param usSessionInfoIndex    - (Input) session info index
         * @param usOppDevCertIndex     - (Input) opponent certificate index
         * @param usOppSubCaCertIndex   - (Input) opponent sub CA certificate index
         * @param usEkmIndex            - (Input) Ekm index
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * - 'bCh' should be 0 ~ 5.
         * - 'bMode' should be one of belows.
         *    < KSETLS_MODE_TLS(0) / KSETLS_MODE_DTLS(1) >
         * - 'bEndpoint' should be one of belows.
         *    < KSETLS_CLIENT(0) / KSETLS_SERVER(1) >
         * - 'usKseDevCertIndex' should be 0 ~ 1023.
         * - 'usKseSubCaCertIndex', 'usKseRootCaCertIndex',
         *   'usSessionInfoIndex', 'usOppDevCertIndex',
         *   'usOppSubCaCertIndex', and 'usEkmIndex' should be
         *    0 ~ 1023 / NO_USE('FFFF').
         * -  When only one certificate is used in TLS/DTLS certificate list,
         *    only one of 'usKseSubCaCertIndex' and 'usKseRootCaCertIndex'
         *    should be used. 'usOppSubCaCertIndex' is not used.
         * -  When two certificates are used in TLS/DTLS certificate list,
         *    all of 'usKseSubCaCertIndex' and 'usKseRootCaCertIndex' should be used.
         *    'usOppSubCaCertIndex' could be used.
         * -  If 'usKseDevCertIndex', 'usKseSubCaCertIndex', or 'usKseRootCaCertIndex'
         *    are used, the certificate and public key should be in the certificate
         *    and public key area of the specified index.
         * -  If 'usSessionInfoIndex' is used, when a full handshake is performed,
         *    the generated session information will be stored in the kseTLS
         *    information area of 'usSessionInfoIndex'. When an abbreviated handshake
         *    is performed, the stored session information in the kseTLS information
         *    area of 'usSessionInfoIndex' will be read and used.
         * -  If 'usOppDevCertIndex' is used, the opponent device certificate and
         *    public key received in the full handshake process are stored in the
         *    certificate and public key area of 'usOppDevCertIndex'. At this time,
         *    the certificate and public key area of 'usOppDevCertIndex' should be
         *    empty.
         * -  If 'usOppSubCaCertIndex' is used, the opponent Sub-CA certificate and
         *    public key received in the full handshake process are stored in the
         *    certificate and public key area of 'usOppSubCaCertIndex'. At this time,
         *    the certificate and public key area of 'usOppSubCaCertIndex' should be
         *    empty.
         * -  If 'usEkmIndex' is used, the generated EKM(Exported Keying Material) in
         *    the full handshake process are stored in the AMI key area of
         *    'usEkmIndex'. At this time, the AMI key area of 'usEkmIndex' should be
         *    empty.
         * -  This method can be used only in the 'ISSUED User' state.
         * -  If error, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KsetlsOpen = function (bCh, bMode, bEndpoint, usKseDevCertIndex, usKseSubCaCertIndex, usKseRootCaCertIndex, usSessionInfoIndex, usOppDevCertIndex, usOppSubCaCertIndex, usEkmIndex) { return __awaiter(_this, void 0, void 0, function () {
            var abTxData, abRxData, sLen, sRv;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        // await this.MutexLock(this.gaTlsMutex[bCh]);
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        // Check KSE power state.
                        if (this.gsKsePower !== this.KSE_POWER_ON) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        // Check input.
                        if (bCh >= KseDim.MAX_CHANNEL_COUNT ||
                            (bMode !== KseDim.KSETLS_MODE_TLS && bMode !== KseDim.KSETLS_MODE_DTLS) ||
                            (bEndpoint !== KseDim.KSETLS_CLIENT &&
                                bEndpoint !== KseDim.KSETLS_SERVER) ||
                            usKseDevCertIndex >= KseDim.MAX_CERT_KEY_COUNT ||
                            (usKseSubCaCertIndex !== KseDim.NO_USE &&
                                usKseSubCaCertIndex >= KseDim.MAX_CERT_KEY_COUNT) ||
                            (usKseRootCaCertIndex !== KseDim.NO_USE &&
                                usKseRootCaCertIndex >= KseDim.MAX_CERT_KEY_COUNT) ||
                            (usSessionInfoIndex !== KseDim.NO_USE &&
                                usSessionInfoIndex >= KseDim.MAX_CERT_KEY_COUNT) ||
                            (usOppDevCertIndex !== KseDim.NO_USE &&
                                usOppDevCertIndex >= KseDim.MAX_CERT_KEY_COUNT) ||
                            (usOppSubCaCertIndex !== KseDim.NO_USE &&
                                usOppSubCaCertIndex >= KseDim.MAX_CERT_KEY_COUNT) ||
                            (usEkmIndex !== KseDim.NO_USE && usEkmIndex >= KseDim.MAX_CERT_KEY_COUNT)) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        abTxData = new Array(19);
                        abTxData[0] = 0x06;
                        abTxData[1] = 0x00;
                        abTxData[2] = bCh & 0xff;
                        abTxData[3] = bMode & 0xff;
                        abTxData[4] = bEndpoint & 0xff;
                        abTxData[5] = (usKseDevCertIndex >> 8) & 0xff;
                        abTxData[6] = usKseDevCertIndex & 0xff;
                        abTxData[7] = (usKseSubCaCertIndex >> 8) & 0xff;
                        abTxData[8] = usKseSubCaCertIndex & 0xff;
                        abTxData[9] = (usKseRootCaCertIndex >> 8) & 0xff;
                        abTxData[10] = usKseRootCaCertIndex & 0xff;
                        abTxData[11] = (usSessionInfoIndex >> 8) & 0xff;
                        abTxData[12] = usSessionInfoIndex & 0xff;
                        abTxData[13] = (usOppDevCertIndex >> 8) & 0xff;
                        abTxData[14] = usOppDevCertIndex & 0xff;
                        abTxData[15] = (usOppSubCaCertIndex >> 8) & 0xff;
                        abTxData[16] = usOppSubCaCertIndex & 0xff;
                        abTxData[17] = (usEkmIndex >> 8) & 0xff;
                        abTxData[18] = usEkmIndex & 0xff;
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 1:
                        abRxData = _a.sent();
                        if (!abRxData) {
                            this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sLen = abRxData.length;
                        if (sLen !== 2) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (sRv !== KseDim.KSE_SUCCESS) {
                            this.gsKseLastErrorCode = sRv;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        // Backup end point.
                        this.gabEndpoint[bCh] = bEndpoint;
                        this.gausNetDataLength[bCh] = 0;
                        // await this.MutexRelease(this.gaTlsMutex[bCh]);
                        return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * <kseTLS> Resets a kseTLS channel.
         *
         * @param bCh       - (Input) channel
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * - 'bCh' should be 0 ~ 5.
         * -  This method can be used only in the 'ISSUED User' state.
         * -  If an error occurs, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KsetlsReset = function (bCh) { return __awaiter(_this, void 0, void 0, function () {
            var abTxData, abRxData, sLen, sRv;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        // await this.MutexLock(this.gaTlsMutex[bCh]);
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        // Check KSE power state.
                        if (this.gsKsePower !== this.KSE_POWER_ON) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        // Check input.
                        if (bCh >= KseDim.MAX_CHANNEL_COUNT) {
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL_WRONG_INPUT];
                        }
                        abTxData = new Array(3);
                        abTxData[0] = 0x06;
                        abTxData[1] = 0x01;
                        abTxData[2] = bCh;
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 1:
                        abRxData = _a.sent();
                        if (!abRxData) {
                            this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sLen = abRxData.length;
                        if (sLen !== 2) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (sRv !== KseDim.KSE_SUCCESS) {
                            this.gsKseLastErrorCode = sRv;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        this.gausNetDataLength[bCh] = 0;
                        // await this.MutexRelease(this.gaTlsMutex[bCh]);
                        return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * <kseTLS> Closes a kseTLS channel.
         *
         * @param bCh       - (Input) channel
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * - 'bCh' should be 0 ~ 5.
         * -  This method can be used only in the 'ISSUED User' state.
         * -  If an error occurs, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KsetlsClose = function (bCh) { return __awaiter(_this, void 0, void 0, function () {
            var abTxData, abRxData, sLen, sRv;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        // await this.MutexLock(this.gaTlsMutex[bCh]);
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        // Check KSE power state.
                        if (this.gsKsePower !== this.KSE_POWER_ON) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        // Check input.
                        if (bCh >= KseDim.MAX_CHANNEL_COUNT) {
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL_WRONG_INPUT];
                        }
                        abTxData = new Array(3);
                        abTxData[0] = 0x06;
                        abTxData[1] = 0x02;
                        abTxData[2] = bCh;
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 1:
                        abRxData = _a.sent();
                        if (!abRxData) {
                            this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sLen = abRxData.length;
                        if (sLen !== 2) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (sRv !== KseDim.KSE_SUCCESS) {
                            this.gsKseLastErrorCode = sRv;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        this.gausNetDataLength[bCh] = 0;
                        // await this.MutexRelease(this.gaTlsMutex[bCh]);
                        return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * <kseTLS> TLS Client Handshake.
         *
         * @param clientId          - (Input) client id
         * @param bCh               - (Input) channel
         * @param bType             - (Input) full or abbreviated type
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * - 'bCh' should be 0 ~ 5.
         * - 'bType' should be one of the followings.
         * < KSETLS_FULL_HANDSHAKE(0) / KSETLS_ABBR_HANDSHAKE(1) >
         * -  If 'bType' is KSETLS_FULL_HANDSHAKE, TLS client and server perform a
         * full handshake.
         * -  If 'bType' is KSETLS_ABBR_HANDSHAKE, TLS client and server perform an
         * abbreviated handshake(a session resuming).
         * -  This method can be used only in the 'ISSUED User state.
         * -  If an error occurs, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KsetlsTlsClientHandshake = function (clientId, bCh, bType) { return __awaiter(_this, void 0, void 0, function () {
            var abTxData, abRxData, sRv, sInLen, sOutLen, usLen, usRecordLen, usUnusedInputLen, bNextInput;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.MutexLock(this.gaTlsMutex[bCh])];
                    case 1:
                        _a.sent();
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        if (!(this.gsKsePower !== this.KSE_POWER_ON)) return [3 /*break*/, 3];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 2:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 3:
                        if (!(!clientId ||
                            bCh >= KseDim.MAX_CHANNEL_COUNT ||
                            (bType !== KseDim.KSETLS_FULL_HANDSHAKE &&
                                bType !== KseDim.KSETLS_ABBR_HANDSHAKE))) return [3 /*break*/, 5];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 4:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 5:
                        bNextInput = KseDim.KSE_FALSE;
                        this.gausNetDataLength[bCh] = 0;
                        _a.label = 6;
                    case 6:
                        if (!(bNextInput === KseDim.KSE_TRUE)) return [3 /*break*/, 12];
                        if (!(this.gausNetDataLength[bCh] === 0)) return [3 /*break*/, 10];
                        return [4 /*yield*/, this.TlsRecv(KseDim.KSETLS_DATA_HANDSHAKE, this.gaabNetData[bCh], clientId, bCh, KseDim.KSETLS_TIMEOUT)];
                    case 7:
                        sInLen = _a.sent();
                        if (!(sInLen < 0)) return [3 /*break*/, 9];
                        this.gsKseLastErrorCode = sInLen;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 8:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 9: return [3 /*break*/, 11];
                    case 10:
                        sInLen = this.gausNetDataLength[bCh];
                        _a.label = 11;
                    case 11: return [3 /*break*/, 13];
                    case 12:
                        sInLen = 0;
                        _a.label = 13;
                    case 13:
                        // Process Handshake.
                        abTxData = new Array(sInLen + 6);
                        abTxData[0] = 0x06;
                        abTxData[1] = 0x10;
                        abTxData[2] = bCh;
                        abTxData[3] = bType;
                        abTxData[4] = (sInLen >> 8) & 0xff;
                        abTxData[5] = sInLen & 0xff;
                        if (sInLen > 0)
                            this.ArrayCopy(this.gaabNetData[bCh], 0, abTxData, 6, sInLen);
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 14:
                        abRxData = _a.sent();
                        if (!!abRxData) return [3 /*break*/, 16];
                        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 15:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 16:
                        usLen = abRxData.length;
                        if (!(usLen < 2)) return [3 /*break*/, 18];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 17:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 18:
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (!(sRv === KseDim.KSE_SUCCESS && usLen < 7)) return [3 /*break*/, 20];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 19:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 20:
                        if (usLen > 2) {
                            usUnusedInputLen = (abRxData[2] << 8) | abRxData[3];
                            bNextInput = abRxData[4];
                            usRecordLen = (abRxData[5] << 8) | abRxData[6];
                        }
                        else {
                            usUnusedInputLen = 0;
                            bNextInput = KseDim.KSE_FALSE;
                            usRecordLen = 0;
                        }
                        if (!(usRecordLen > 0)) return [3 /*break*/, 23];
                        abTxData = new Array(usRecordLen);
                        this.ArrayCopy(abRxData, 7, abTxData, 0, usRecordLen);
                        return [4 /*yield*/, this.TlsSend(KseDim.KSETLS_DATA_HANDSHAKE, clientId, bCh, abTxData)];
                    case 21:
                        sOutLen = _a.sent();
                        if (!(sOutLen < 0)) return [3 /*break*/, 23];
                        this.gsKseLastErrorCode = sOutLen;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 22:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 23:
                        // Next.
                        if (usUnusedInputLen > 0) {
                            abRxData = new Array(usUnusedInputLen);
                            this.ArrayCopy(this.gaabNetData[bCh], sInLen - usUnusedInputLen, abRxData, 0, usUnusedInputLen);
                            this.ArrayCopy(abRxData, 0, this.gaabNetData[bCh], 0, usUnusedInputLen);
                            this.gausNetDataLength[bCh] = usUnusedInputLen;
                        }
                        else
                            this.gausNetDataLength[bCh] = usUnusedInputLen;
                        _a.label = 24;
                    case 24:
                        if (sRv === KseDim.KSE_SUCCESS) return [3 /*break*/, 6];
                        _a.label = 25;
                    case 25:
                        if (sRv === KseDim.KSETLS_HANDSHAKE_DONE)
                            sRv = KseDim.KSE_SUCCESS;
                        if (!(sRv !== KseDim.KSE_SUCCESS)) return [3 /*break*/, 27];
                        this.gsKseLastErrorCode = sRv;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 26:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 27: return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 28:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * <kseTLS> TLS Server Handshake.
         *
         * @param clientId          - (Input) client id
         * @param bCh               - (Input) channel
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * - 'bCh' should be 0 ~ 5.
         * -  This method can be used only in the 'ISSUED User state.
         * -  If an error occurs, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KsetlsTlsServerHandshake = function (clientId, bCh) { return __awaiter(_this, void 0, void 0, function () {
            var abTxData, abRxData, sRv, sInLen, sOutLen, usLen, usRecordLen, usUnusedInputLen, bNextInput;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        // await this.MutexLock(this.gaTlsMutex[bCh]);
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        // Check KSE power state.
                        if (this.gsKsePower !== this.KSE_POWER_ON) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        // Check input.
                        if (!clientId || bCh >= KseDim.MAX_CHANNEL_COUNT) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        bNextInput = KseDim.KSE_TRUE;
                        this.gausNetDataLength[bCh] = 0;
                        _a.label = 1;
                    case 1:
                        if (!(bNextInput === KseDim.KSE_TRUE)) return [3 /*break*/, 5];
                        if (!(this.gausNetDataLength[bCh] === 0)) return [3 /*break*/, 3];
                        return [4 /*yield*/, this.TlsRecv(KseDim.KSETLS_DATA_HANDSHAKE, this.gaabNetData[bCh], clientId, bCh, KseDim.KSETLS_TIMEOUT)];
                    case 2:
                        sInLen = _a.sent();
                        if (sInLen < 0) {
                            this.gsKseLastErrorCode = sInLen;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        return [3 /*break*/, 4];
                    case 3:
                        sInLen = this.gausNetDataLength[bCh];
                        _a.label = 4;
                    case 4: return [3 /*break*/, 6];
                    case 5:
                        sInLen = 0;
                        _a.label = 6;
                    case 6:
                        // Process Handshake.
                        abTxData = new Array(sInLen + 5);
                        abTxData[0] = 0x06;
                        abTxData[1] = 0x11;
                        abTxData[2] = bCh;
                        abTxData[3] = (sInLen >> 8) & 0xff;
                        abTxData[4] = sInLen & 0xff;
                        if (sInLen > 0)
                            this.ArrayCopy(this.gaabNetData[bCh], 0, abTxData, 5, sInLen);
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 7:
                        abRxData = _a.sent();
                        if (!abRxData) {
                            this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        usLen = abRxData.length;
                        if (usLen < 2) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (sRv === KseDim.KSE_SUCCESS && usLen < 7) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        if (usLen > 2) {
                            usUnusedInputLen = (abRxData[2] << 8) | abRxData[3];
                            bNextInput = abRxData[4];
                            usRecordLen = (abRxData[5] << 8) | abRxData[6];
                        }
                        else {
                            usUnusedInputLen = 0;
                            bNextInput = KseDim.KSE_FALSE;
                            usRecordLen = 0;
                        }
                        if (!(usRecordLen > 0)) return [3 /*break*/, 9];
                        abTxData = new Array(usRecordLen);
                        this.ArrayCopy(abRxData, 7, abTxData, 0, usRecordLen);
                        return [4 /*yield*/, this.TlsSend(KseDim.KSETLS_DATA_HANDSHAKE, clientId, bCh, abTxData)];
                    case 8:
                        sOutLen = _a.sent();
                        if (sOutLen < 0) {
                            this.gsKseLastErrorCode = sOutLen;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        _a.label = 9;
                    case 9:
                        // Next.
                        if (usUnusedInputLen > 0) {
                            abRxData = new Array(usUnusedInputLen);
                            this.ArrayCopy(this.gaabNetData[bCh], sInLen - usUnusedInputLen, abRxData, 0, usUnusedInputLen);
                            this.ArrayCopy(abRxData, 0, this.gaabNetData[bCh], 0, usUnusedInputLen);
                            this.gausNetDataLength[bCh] = usUnusedInputLen;
                        }
                        else
                            this.gausNetDataLength[bCh] = 0;
                        _a.label = 10;
                    case 10:
                        if (sRv === KseDim.KSE_SUCCESS) return [3 /*break*/, 1];
                        _a.label = 11;
                    case 11:
                        if (sRv === KseDim.KSETLS_HANDSHAKE_DONE)
                            sRv = KseDim.KSE_SUCCESS;
                        if (sRv !== KseDim.KSE_SUCCESS) {
                            this.gsKseLastErrorCode = sRv;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        // await this.MutexRelease(this.gaTlsMutex[bCh]);
                        return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * <kseTLS> Opens a kseTLS channel and start server handshake.
         *
         * @param bCh                   - (Input) channel
         * @param bMode                 - (Input) TLS or DTLS mode
         * @param bEndpoint             - (Input) client or server endpoint
         * @param usKseDevCertIndex     - (Input) development certificate index
         * @param usKseSubCaCertIndex   - (Input) sub CA certificate index
         * @param usKseRootCaCertIndex  - (Input) root CA certificate index
         * @param usSessionInfoIndex    - (Input) session info index
         * @param usOppDevCertIndex     - (Input) opponent certificate index
         * @param usOppSubCaCertIndex   - (Input) opponent sub CA certificate index
         * @param usEkmIndex            - (Input) Ekm index
         * @param clientId              - (Input) client ID
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * - 'bCh' should be 0 ~ 5.
         * - 'bMode' should be one of belows.
         *    < KSETLS_MODE_TLS(0) / KSETLS_MODE_DTLS(1) >
         * - 'bEndpoint' should be one of belows.
         *    < KSETLS_CLIENT(0) / KSETLS_SERVER(1) >
         * - 'usKseDevCertIndex' should be 0 ~ 1023.
         * - 'usKseSubCaCertIndex', 'usKseRootCaCertIndex',
         *   'usSessionInfoIndex', 'usOppDevCertIndex',
         *   'usOppSubCaCertIndex', and 'usEkmIndex' should be
         *    0 ~ 1023 / NO_USE('FFFF').
         * -  When only one certificate is used in TLS/DTLS certificate list,
         *    only one of 'usKseSubCaCertIndex' and 'usKseRootCaCertIndex'
         *    should be used. 'usOppSubCaCertIndex' is not used.
         * -  When two certificates are used in TLS/DTLS certificate list,
         *    all of 'usKseSubCaCertIndex' and 'usKseRootCaCertIndex' should be used.
         *    'usOppSubCaCertIndex' could be used.
         * -  If 'usKseDevCertIndex', 'usKseSubCaCertIndex', or 'usKseRootCaCertIndex'
         *    are used, the certificate and public key should be in the certificate
         *    and public key area of the specified index.
         * -  If 'usSessionInfoIndex' is used, when a full handshake is performed,
         *    the generated session information will be stored in the kseTLS
         *    information area of 'usSessionInfoIndex'. When an abbreviated handshake
         *    is performed, the stored session information in the kseTLS information
         *    area of 'usSessionInfoIndex' will be read and used.
         * -  If 'usOppDevCertIndex' is used, the opponent device certificate and
         *    public key received in the full handshake process are stored in the
         *    certificate and public key area of 'usOppDevCertIndex'. At this time,
         *    the certificate and public key area of 'usOppDevCertIndex' should be
         *    empty.
         * -  If 'usOppSubCaCertIndex' is used, the opponent Sub-CA certificate and
         *    public key received in the full handshake process are stored in the
         *    certificate and public key area of 'usOppSubCaCertIndex'. At this time,
         *    the certificate and public key area of 'usOppSubCaCertIndex' should be
         *    empty.
         * -  If 'usEkmIndex' is used, the generated EKM(Exported Keying Material) in
         *    the full handshake process are stored in the AMI key area of
         *    'usEkmIndex'. At this time, the AMI key area of 'usEkmIndex' should be
         *    empty.
         * -  This method can be used only in the 'ISSUED User' state.
         * -  If error, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KsetlsOpenAndServerHandshake = function (bCh, bMode, bEndpoint, usKseDevCertIndex, usKseSubCaCertIndex, usKseRootCaCertIndex, usSessionInfoIndex, usOppDevCertIndex, usOppSubCaCertIndex, usEkmIndex, clientId) { return __awaiter(_this, void 0, void 0, function () {
            var sRv;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.KsetlsOpen(bCh, bMode, bEndpoint, usKseDevCertIndex, usKseSubCaCertIndex, usKseRootCaCertIndex, usSessionInfoIndex, usOppDevCertIndex, usOppSubCaCertIndex, usEkmIndex)];
                    case 1:
                        sRv = _a.sent();
                        if (sRv !== KseDim.KSE_SUCCESS) {
                            console.log("  KsetlsOpen() error.");
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        console.log("KsetlsOpen() : Success...");
                        console.log("  * Performing the TLS handshake...");
                        return [4 /*yield*/, this.KsetlsTlsServerHandshake(clientId, bCh)];
                    case 2:
                        sRv = _a.sent();
                        if (sRv !== KseDim.KSE_SUCCESS) {
                            console.log("  KsetlsTlsServerHandshake() error.");
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        console.log("KsetlsTlsServerHandshake() : Success...");
                        return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * <kseTLS> TLS Reads Application Data.
         *
         * @param clientId          - (Input) client id
         * @param bCh               - (Input) channel
         * @returns `received application data` or `null`
         *
         * ```
         * Description:
         * -  This method can be used only in the 'ISSUED User state.
         * -  If an error occurs, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KsetlsTlsRead = function (clientId, bCh) { return __awaiter(_this, void 0, void 0, function () {
            var sRv, sInLen, sOutLen, abTxData, abRxData, abInAppData, usLen, usRecordLen, usUnusedInputLen, usMessageLen;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.MutexLock(this.gaTlsMutex[bCh])];
                    case 1:
                        _a.sent();
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        if (!(this.gsKsePower !== this.KSE_POWER_ON)) return [3 /*break*/, 3];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 2:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 3:
                        if (!(!clientId || bCh >= KseDim.MAX_CHANNEL_COUNT)) return [3 /*break*/, 5];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 4:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 5:
                        if (!(this.gausNetDataLength[bCh] === 0)) return [3 /*break*/, 7];
                        return [4 /*yield*/, this.TlsRecv(KseDim.KSETLS_DATA_ENCRYPT, this.gaabNetData[bCh], clientId, bCh, KseDim.KSETLS_TIMEOUT)];
                    case 6:
                        // Receive Record.
                        sInLen = _a.sent();
                        if (sInLen < 0) {
                            this.gsKseLastErrorCode = sInLen;
                            return [2 /*return*/, null];
                        }
                        return [3 /*break*/, 8];
                    case 7:
                        sInLen = this.gausNetDataLength[bCh];
                        _a.label = 8;
                    case 8:
                        // Parse Record.
                        abTxData = new Array(sInLen + 5);
                        abTxData[0] = 0x06;
                        abTxData[1] = 0x20;
                        abTxData[2] = bCh;
                        abTxData[3] = (sInLen >> 8) & 0xff;
                        abTxData[4] = sInLen & 0xff;
                        if (sInLen > 0)
                            this.ArrayCopy(this.gaabNetData[bCh], 0, abTxData, 5, sInLen);
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 9:
                        abRxData = _a.sent();
                        if (!!abRxData) return [3 /*break*/, 11];
                        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 10:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 11:
                        usLen = abRxData.length;
                        if (!(usLen < 2)) return [3 /*break*/, 13];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 12:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 13:
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (!((sRv === KseDim.KSE_SUCCESS && usLen < 6) ||
                            (sRv !== KseDim.KSE_SUCCESS && usLen !== 2 && usLen !== 4))) return [3 /*break*/, 15];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 14:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 15:
                        if (!(sRv !== KseDim.KSE_SUCCESS)) return [3 /*break*/, 29];
                        if (!(usLen === 4)) return [3 /*break*/, 27];
                        // Set Alert.
                        abTxData = new Array(5);
                        abTxData[4] = abRxData[3];
                        abTxData[3] = abRxData[2];
                        abTxData[0] = 0x06;
                        abTxData[1] = 0x22;
                        abTxData[2] = bCh;
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 16:
                        abRxData = _a.sent();
                        if (!!abRxData) return [3 /*break*/, 18];
                        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 17:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 18:
                        usLen = abRxData.length;
                        if (!(usLen < 2)) return [3 /*break*/, 20];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 19:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 20:
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (!((sRv === KseDim.KSE_SUCCESS && usLen < 4) ||
                            (sRv !== KseDim.KSE_SUCCESS && usLen !== 2))) return [3 /*break*/, 22];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 21:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 22:
                        if (!(sRv !== KseDim.KSE_SUCCESS)) return [3 /*break*/, 24];
                        this.gsKseLastErrorCode = sRv;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 23:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 24:
                        usRecordLen = (abRxData[2] << 8) | abRxData[3];
                        if (!(usRecordLen > 0)) return [3 /*break*/, 27];
                        abTxData = new Array(usRecordLen);
                        this.ArrayCopy(abRxData, 4, abTxData, 0, usRecordLen);
                        return [4 /*yield*/, this.TlsSend(KseDim.KSETLS_DATA_WARNING, clientId, bCh, abTxData)];
                    case 25:
                        sOutLen = _a.sent();
                        if (!(sOutLen < 0)) return [3 /*break*/, 27];
                        this.gsKseLastErrorCode = sOutLen;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 26:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 27:
                        this.gausNetDataLength[bCh] = 0;
                        this.gsKseLastErrorCode = sRv;
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 28:
                        _a.sent();
                        return [2 /*return*/, null];
                    case 29:
                        usUnusedInputLen = (abRxData[2] << 8) | abRxData[3];
                        usMessageLen = (abRxData[4] << 8) | abRxData[5];
                        abInAppData = new Array(usMessageLen);
                        this.ArrayCopy(abRxData, 6, abInAppData, 0, usMessageLen);
                        if (usUnusedInputLen > 0) {
                            abRxData = new Array(usUnusedInputLen);
                            this.ArrayCopy(this.gaabNetData[bCh], sInLen - usUnusedInputLen, abRxData, 0, usUnusedInputLen);
                            this.ArrayCopy(abRxData, 0, this.gaabNetData[bCh], 0, usUnusedInputLen);
                            this.gausNetDataLength[bCh] = usUnusedInputLen;
                        }
                        else {
                            this.gausNetDataLength[bCh] = 0;
                        }
                        return [4 /*yield*/, this.MutexRelease(this.gaTlsMutex[bCh])];
                    case 30:
                        _a.sent();
                        return [2 /*return*/, abInAppData];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * <kseTLS> TLS Reads Application Data.
         *
         * @param clientId          - (Input) client id
         * @param bCh               - (Input) channel
         * @param abOutAppData      - (Input) application data to write
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * - 'bCh' should be 0 ~ 5.
         * - 'abOutAppData.length' should be 1 ~ 2944.
         * -  This method can be used only in the 'ISSUED User state.
         * -  If an error occurs, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KsetlsTlsWrite = function (clientId, bCh, abOutAppData) { return __awaiter(_this, void 0, void 0, function () {
            var sOutAppDataLen, sRv, sOutLen, abTxData, abRxData, usLen, usRecordLen;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        // await this.MutexLock(this.gaTlsMutex[bCh]);
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        // Check KSE power state.
                        if (this.gsKsePower !== this.KSE_POWER_ON) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        // Check input.
                        if (!clientId ||
                            bCh >= KseDim.MAX_CHANNEL_COUNT ||
                            !abOutAppData ||
                            abOutAppData.length === 0 ||
                            abOutAppData.length > KseDim.MAX_IO_DATA_SIZE) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sOutAppDataLen = abOutAppData.length;
                        sOutLen = 0;
                        // Set Record.
                        abTxData = new Array(sOutAppDataLen + 5);
                        abTxData[0] = 0x06;
                        abTxData[1] = 0x21;
                        abTxData[2] = bCh;
                        abTxData[3] = (sOutAppDataLen >> 8) & 0xff;
                        abTxData[4] = sOutAppDataLen & 0xff;
                        this.ArrayCopy(abOutAppData, 0, abTxData, 5, sOutAppDataLen);
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 1:
                        abRxData = _a.sent();
                        if (!abRxData) {
                            this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        usLen = abRxData.length;
                        if (usLen < 2) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if ((sRv === KseDim.KSE_SUCCESS && usLen < 4) ||
                            (sRv !== KseDim.KSE_SUCCESS && usLen !== 2)) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        if (sRv !== KseDim.KSE_SUCCESS) {
                            this.gsKseLastErrorCode = sRv;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        usRecordLen = (abRxData[2] << 8) | abRxData[3];
                        if (!(usRecordLen > 0)) return [3 /*break*/, 3];
                        abTxData = new Array(usRecordLen);
                        this.ArrayCopy(abRxData, 4, abTxData, 0, usRecordLen);
                        return [4 /*yield*/, this.TlsSend(KseDim.KSETLS_DATA_ENCRYPT, clientId, bCh, abTxData)];
                    case 2:
                        sOutLen = _a.sent();
                        if (sOutLen < 0) {
                            this.gsKseLastErrorCode = sOutLen;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        _a.label = 3;
                    case 3:
                        this.gausNetDataLength[bCh] = 0;
                        // await this.MutexRelease(this.gaTlsMutex[bCh]);
                        return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * <kseTLS> TLS Write Close Notify.
         *
         * @param clientId          - (Input) client id
         * @param bCh               - (Input) channel
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * - 'bCh' should be 0 ~ 5.
         * -  This method can be used only in the 'ISSUED User state.
         * -  If an error occurs, 'gsKseLastErrorCode' would be set.
         * ```
         * -------------------------------------------------------------------------*/
        this.KsetlsTlsCloseNotify = function (clientId, bCh) { return __awaiter(_this, void 0, void 0, function () {
            var sRv, sOutLen, abTxData, abRxData, usLen, usRecordLen;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        // await this.MutexLock(this.gaTlsMutex[bCh]);
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        // Check KSE power state.
                        if (this.gsKsePower !== this.KSE_POWER_ON) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        // Check input.
                        if (!clientId || bCh >= KseDim.MAX_CHANNEL_COUNT) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sOutLen = 0;
                        // Close notify.
                        abTxData = new Array(6);
                        abTxData[0] = 0x06;
                        abTxData[1] = 0x23;
                        abTxData[2] = bCh;
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 1:
                        abRxData = _a.sent();
                        if (abRxData === null) {
                            this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        usLen = abRxData.length;
                        if (usLen < 2) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if ((sRv === KseDim.KSE_SUCCESS && usLen < 4) ||
                            (sRv !== KseDim.KSE_SUCCESS && usLen !== 2)) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        if (sRv !== KseDim.KSE_SUCCESS) {
                            this.gsKseLastErrorCode = sRv;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        usRecordLen = (abRxData[2] << 8) | abRxData[3];
                        if (!(usRecordLen > 0)) return [3 /*break*/, 3];
                        abTxData = new Array(usRecordLen);
                        this.ArrayCopy(abRxData, 4, abTxData, 0, usRecordLen);
                        return [4 /*yield*/, this.TlsSend(KseDim.KSETLS_DATA_CLOSE, clientId, bCh, abTxData)];
                    case 2:
                        sOutLen = _a.sent();
                        if (sOutLen < 0) {
                            this.gsKseLastErrorCode = sOutLen;
                            // await this.MutexRelease(this.gaTlsMutex[bCh]);
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        _a.label = 3;
                    case 3:
                        this.gausNetDataLength[bCh] = 0;
                        // await this.MutexRelease(this.gaTlsMutex[bCh]);
                        return [2 /*return*/, sOutLen];
                }
            });
        }); };
        //// DID /////////////////////////////////////////////////////////////////////
        /**---------------------------------------------------------------------------
         * <dimDid> Write Drone ID.
         *
         * @param abDid          - (Input) drone id
         * @param sDidLen        - (Input) drone id length
         * @param sDidIndex      - (Input) drone id index
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * -  'sDidLen' should be 0 ~ 32.
         * -  If 'abDid' === null, 'sDidLen' should be 0.
         * -  If 'abDid' !== null, 'abDid' should be 'sDidLen'-byte array.
         * -  'sDidIndex' should be 0 ~ 7.
         * ```
         * -------------------------------------------------------------------------*/
        this.DimDidWrite = function (abDid, sDidLen, sDidIndex) { return __awaiter(_this, void 0, void 0, function () {
            var sRv, abTxData, abRxData, sLen;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.MutexLock(this.gKcmvpMutex)];
                    case 1:
                        _a.sent();
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        if (!(this.gsKsePower !== this.KSE_POWER_ON)) return [3 /*break*/, 3];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 2:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 3:
                        if (!(sDidLen > 32 ||
                            (sDidLen === 0 && abDid !== null) ||
                            sDidIndex >= KseDim.MAX_DRONE_ID_COUNT)) return [3 /*break*/, 5];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 4:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 5:
                        // Write Drone ID.
                        abTxData = new Array(5 + sDidLen);
                        abTxData[0] = 0x0c;
                        abTxData[1] = 0x00;
                        abTxData[2] = (sDidIndex >> 8) & 0xff;
                        abTxData[3] = sDidIndex & 0xff;
                        abTxData[4] = sDidLen & 0xff;
                        this.ArrayCopy(abDid, 0, abTxData, 5, sDidLen);
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 6:
                        abRxData = _a.sent();
                        if (!(abRxData === null)) return [3 /*break*/, 8];
                        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 7:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 8:
                        sLen = abRxData.length;
                        if (!(sLen !== 2)) return [3 /*break*/, 10];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 9:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 10:
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (!(sRv !== KseDim.KSE_SUCCESS)) return [3 /*break*/, 12];
                        this.gsKseLastErrorCode = sRv;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 11:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 12: return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 13:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * <dimDid> Read Drone ID.
         *
         * @param outabDid         - (Output) drone id
         * @param outsDidLen       - (Output) drone id length
         * @param outabAuthCode    - (Output) authentication code
         * @param sDidIndex        - (Input) drone id index
         * @param bDidType         - (Input) drone id type
         * @param sKeyIndex        - (Input) key index
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * -  'sDidIndex' should be 0 ~ 7.
         * -  'bDidType' should be one of the belows.
         *    < DID_ONLY('00') / DID_ECDSA('01') / DID_HMAC('02') >
         * -  If 'bDidType' is DID_ONLY, 'sKeyIndex' should be 0.
         * -  If 'bDidType' is DID_ECDSA and 'sKeyIndex' is KCMVP ECDSA key index,
         *    'sKeyIndex' should be 0 ~ 7.
         * -  If 'bDidType' is DID_ECDSA and 'sKeyIndex' is Certificate key index,
         *    'sKeyIndex' should be 0x8000 + 0 ~ 95.
         * -  If 'bDidType' is DID_HMAC, 'sKeyIndex' should be 0 ~ 7.
         * -  'outabDid' should be 32-byte array for max 32-byte Drone ID.
         * -  If 'bDidType' is DID_ONLY, 'outabAuthCode' is not used.
         * -  If 'bDidType' is DID_ECDSA, 'outabAuthCode' should be 64-byte array.
         * -  If 'bDidType' is DID_HMAC, 'outabAuthCode' should be 32-byte array.
         * ```
         * -------------------------------------------------------------------------*/
        this.DimDidRead = function (outabDid, outsDidLen, outabAuthCode, sDidIndex, bDidType, sKeyIndex) { return __awaiter(_this, void 0, void 0, function () {
            var sKeyType, sKeyIndexMask, abTxData, abRxData, sLen, sRv, sDidLen;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.MutexLock(this.gKcmvpMutex)];
                    case 1:
                        _a.sent();
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        if (!(this.gsKsePower !== this.KSE_POWER_ON)) return [3 /*break*/, 3];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 2:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 3:
                        sKeyType = sKeyIndex >> 15;
                        sKeyIndexMask = sKeyIndex & 0x7fff;
                        if (!(outabDid === null ||
                            sDidIndex >= KseDim.MAX_DRONE_ID_COUNT ||
                            bDidType > KseDim.DID_HMAC ||
                            (bDidType === KseDim.DID_ONLY && sKeyIndex !== 0) ||
                            (bDidType === KseDim.DID_ECDSA &&
                                ((sKeyType === 0 && sKeyIndexMask >= KseDim.MAX_KCMVP_KEY_COUNT) ||
                                    (sKeyType === 1 && sKeyIndexMask >= KseDim.MAX_CERT_KEY_COUNT))) ||
                            (bDidType === KseDim.DID_HMAC && sKeyIndex >= KseDim.MAX_KCMVP_KEY_COUNT))) return [3 /*break*/, 5];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 4:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 5:
                        abTxData = new Array(7);
                        abTxData[0] = 0x0c;
                        abTxData[1] = 0x01;
                        abTxData[2] = (sDidIndex >> 8) & 0xff;
                        abTxData[3] = sDidIndex & 0xff;
                        abTxData[4] = bDidType;
                        abTxData[5] = (sKeyIndex >> 8) & 0xff;
                        abTxData[6] = sKeyIndex & 0xff;
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 6:
                        abRxData = _a.sent();
                        if (!!abRxData) return [3 /*break*/, 8];
                        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 7:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 8:
                        sLen = abRxData.length;
                        if (!(sLen < 2)) return [3 /*break*/, 10];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 9:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 10:
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        sDidLen = abRxData[2];
                        if (!((sRv === KseDim.KSE_SUCCESS &&
                            ((bDidType === KseDim.DID_ONLY && sLen !== sDidLen + 3) ||
                                (bDidType === KseDim.DID_ECDSA && sLen !== sDidLen + 67) ||
                                (bDidType === KseDim.DID_HMAC && sLen !== sDidLen + 35))) ||
                            (sRv !== KseDim.KSE_SUCCESS && sLen !== 2))) return [3 /*break*/, 12];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 11:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 12:
                        if (!(sRv !== KseDim.KSE_SUCCESS)) return [3 /*break*/, 14];
                        this.gsKseLastErrorCode = sRv;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 13:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 14:
                        outabDid.value = abRxData.slice(3, 3 + sDidLen);
                        if (bDidType === KseDim.DID_ECDSA)
                            outabAuthCode.value = abRxData.slice(3 + sDidLen, 3 + sDidLen + 64);
                        else if (bDidType === KseDim.DID_HMAC)
                            outabAuthCode.value = abRxData.slice(3 + sDidLen, 3 + sDidLen + 32);
                        outsDidLen.value = sDidLen;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 15:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
            });
        }); };
        /**---------------------------------------------------------------------------
         * <dimDid> Verify Drone ID.
         *
         * @param abDid         - (Input) drone id
         * @param sDidLen       - (Input) drone id length
         * @param abAuthCode    - (Input) authentication code
         * @param bDidType         - (Input) drone id type
         * @param sKeyIndex        - (Input) key index
         * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
         *
         * ```
         * Description:
         * -  'usDidLen' should be 1 ~ 32.
         * -  'bDidType' should be one of the belows.
         *    < DID_ONLY('00') / DID_ECDSA('01') / DID_HMAC('02') >
         * -  If 'bDidType' is DID_ECDSA and 'sKeyIndex' is KCMVP ECDSA key index,
         *    'sKeyIndex' should be 0 ~ 7.
         * -  If 'bDidType' is DID_ECDSA and 'sKeyIndex' is Certificate key index,
         *    'sKeyIndex' should be 0x8000 + 0 ~ 95.
         * -  If 'bDidType' is DID_HMAC, 'sKeyIndex' should be 0 ~ 7.
         * -  If 'bDidType' is DID_ECDSA, 'abAuthCode' should be 64-byte array.
         * -  If 'bDidType' is DID_HMAC, 'abAuthCode' should be 32-byte array.
         * ```
         * -------------------------------------------------------------------------*/
        this.DimDidVerify = function (abDid, sDidLen, abAuthCode, bDidType, sKeyIndex) { return __awaiter(_this, void 0, void 0, function () {
            var sKeyType, sKeyIndexMask, sRv, abTxData, abRxData, sLen;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.MutexLock(this.gKcmvpMutex)];
                    case 1:
                        _a.sent();
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        if (!(this.gsKsePower !== this.KSE_POWER_ON)) return [3 /*break*/, 3];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 2:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 3:
                        sKeyType = sKeyIndex >> 15;
                        sKeyIndexMask = sKeyIndex & 0x7fff;
                        if (!(sDidLen === 0 ||
                            sDidLen > 32 ||
                            bDidType < KseDim.DID_ECDSA ||
                            bDidType > KseDim.DID_HMAC ||
                            (bDidType === KseDim.DID_ECDSA &&
                                ((sKeyType === 0 && sKeyIndexMask >= KseDim.MAX_KCMVP_KEY_COUNT) ||
                                    (sKeyType === 1 && sKeyIndexMask >= KseDim.MAX_CERT_KEY_COUNT))) ||
                            (bDidType === KseDim.DID_HMAC &&
                                sKeyIndex >= KseDim.MAX_KCMVP_KEY_COUNT) ||
                            abDid === null ||
                            abAuthCode === null)) return [3 /*break*/, 5];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 4:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 5:
                        // Verify Drone ID.
                        abTxData = new Array(6 + sDidLen + (bDidType === KseDim.DID_ECDSA ? 64 : 32));
                        abTxData[0] = 0x0c;
                        abTxData[1] = 0x02;
                        abTxData[2] = bDidType;
                        abTxData[3] = (sKeyIndex >> 8) & 0xff;
                        abTxData[4] = sKeyIndex & 0xff;
                        abTxData[5] = sDidLen;
                        this.ArrayCopy(abDid, 0, abTxData, 6, sDidLen);
                        if (bDidType === KseDim.DID_ECDSA) {
                            this.ArrayCopy(abAuthCode, 0, abTxData, 6 + sDidLen, 64);
                        }
                        else {
                            this.ArrayCopy(abAuthCode, 0, abTxData, 6 + sDidLen, 32);
                        }
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 6:
                        abRxData = _a.sent();
                        if (!(abRxData === null)) return [3 /*break*/, 8];
                        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 7:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 8:
                        sLen = abRxData.length;
                        if (!(sLen !== 2)) return [3 /*break*/, 10];
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 9:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 10:
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if (!(sRv !== KseDim.KSE_SUCCESS)) return [3 /*break*/, 12];
                        this.gsKseLastErrorCode = sRv;
                        return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 11:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 12: return [4 /*yield*/, this.MutexRelease(this.gKcmvpMutex)];
                    case 13:
                        _a.sent();
                        return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
            });
        }); };
        //// Mutex ///////////////////////////////////////////////////////////////////
        this.MutexLock = function (mutex) { return __awaiter(_this, void 0, void 0, function () {
            var wait_1;
            return __generator(this, function (_a) {
                if (mutex.isLocked) {
                    wait_1 = function (resolve) {
                        if (mutex.isLocked) {
                            setTimeout(function () {
                                wait_1(resolve);
                            }, 50);
                            return;
                        }
                        mutex.isLocked = true;
                        resolve(KseDim.KSE_SUCCESS);
                        return;
                    };
                    return [2 /*return*/, new Promise(function (resolve) {
                            try {
                                wait_1(resolve);
                                return;
                            }
                            catch (e) {
                                mutex.isLocked = true;
                                resolve(KseDim.KSE_FAIL);
                                return;
                            }
                        })];
                }
                else {
                    mutex.isLocked = true;
                    return [2 /*return*/, KseDim.KSE_SUCCESS];
                }
                return [2 /*return*/];
            });
        }); };
        this.MutexRelease = function (mutex) { return __awaiter(_this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                mutex.isLocked = false;
                return [2 /*return*/];
            });
        }); };
        this.tlsReadHanldler = tlsReadHanldler;
        this.tlsWriteHanldler = tlsWriteHanldler;
    }
    /**---------------------------------------------------------------------------
     * Powers on KSE.
     *
     * @param outabVer             - (Output) version
     * @param outbLifeCycle        - (Output) lifecycle
     * @param outabChipSerial      - (Output) chip serial number
     * @param outabSystemTitle     - (Output) system title
     * @param outbVcType           - (Output) vc type
     * @param outbMaxVcRetryCount  - (Output) max vc retry count
     * @param outsMaxChannelCount  - (Output) max channel count
     * @param outsMaxKcmvpKeyCount - (Output) max kcmvp key count
     * @param outsMaxCertKeyCount  - (Output) max certificate key count
     * @param outsMaxIoDataSize    - (Output) max I/O data size
     * @param outiInfoFileSize     - (Output) info file size
     * @returns `KSE_SUCCESS(0)` or `KSE_FAIL(-1)`
     *
     * ```
     * Description:
     * - 'abVer' would be 3-byte array.
     * - 'abChipSerial' would be 8-byte array.
     * - 'abSystemTitle' would be 8-byte array.
     * -  Version will be '011000'. (If sample chip, version will be '0110FF'.)
     * -  LifeCycle would be one of belows.
     *    < LC_MANUFACTURED('FF') / LC_ISSUED('00') / LC_TERMINATED('EE') >
     * -  VcType will be one of belows.
     *    < VC_DISABLED('FF') / VC_TYPE_0('00') / VC_TYPE_1('01') /
     *      VC_TYPE_2('02') / VC_TYPE_3('03') / VC_TYPE_4('04') /
     *      VC_TYPE_5('05') >
     * - 'bMaxVcRetryCount' will be 0(VC_INFINITE) 1 ~ 255.
     * - 'usMaxChannelCount' will be 6.
     * - 'usMaxKcmvpKeyCount' will be 64.
     * - 'usMaxCertKeyCount' will be 1024.
     * - 'usMaxIoDataSize' will be 2944.
     * - 'ulInfoFileSize' will be 1048576.
     * -  If error, 'gsKseLastErrorCode' would be set.
     * ```
     * -------------------------------------------------------------------------*/
    KseDim.prototype.PowerOn = function (outabVer, outbLifeCycle, outabChipSerial, outabSystemTitle, outbVcType, outbMaxVcRetryCount, outsMaxChannelCount, outsMaxKcmvpKeyCount, outsMaxCertKeyCount, outsMaxIoDataSize, outiInfoFileSize) {
        return __awaiter(this, void 0, void 0, function () {
            var deviceList, kseDeviceList, abTxData, abRxData, sLen, sRv, e_9;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        outabVer.value = null;
                        outbLifeCycle.value = 0;
                        outabChipSerial.value = null;
                        outabSystemTitle.value = null;
                        outbVcType.value = 0;
                        outbMaxVcRetryCount.value = 0;
                        outsMaxChannelCount.value = 0;
                        outsMaxKcmvpKeyCount.value = 0;
                        outsMaxCertKeyCount.value = 0;
                        outsMaxIoDataSize.value = 0;
                        outiInfoFileSize.value = 0;
                        this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;
                        // Check KSE power state.
                        if (this.gsKsePower !== this.KSE_POWER_OFF) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_ALREADY_POWERED_ON;
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        deviceList = node_hid_1.default.devices();
                        if (!deviceList || deviceList.length === 0) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_USB_NO_DEVICES;
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        kseDeviceList = this.GetKseDimDeviceList(deviceList);
                        if (!kseDeviceList || kseDeviceList.length === 0) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_FOUND;
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        // Connect DIM.
                        kseDeviceList.every(function (kseDevice) {
                            if (kseDevice.path) {
                                try {
                                    _this.ghDevice = new node_hid_1.default.HID(kseDevice.path);
                                    return false;
                                }
                                catch (e) {
                                    return true;
                                }
                            }
                        });
                        if (!this.ghDevice) {
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_USB_DEVICE_OPEN;
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        abTxData = [0x0a, 0x00];
                        return [4 /*yield*/, this.Transceive(abTxData)];
                    case 1:
                        abRxData = _a.sent();
                        if (!abRxData) {
                            if (this.ghDevice)
                                this.ghDevice.close();
                            this.ghDevice = null;
                            this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sLen = abRxData.length;
                        if (sLen < 2) {
                            if (this.ghDevice)
                                this.ghDevice.close();
                            this.ghDevice = null;
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        sRv = (abRxData[0] << 8) | abRxData[1];
                        if ((sRv === KseDim.KSE_SUCCESS && sLen !== 43) ||
                            (sRv !== KseDim.KSE_SUCCESS && sLen !== 2)) {
                            if (this.ghDevice)
                                this.ghDevice.close();
                            this.ghDevice = null;
                            this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        if (sRv !== KseDim.KSE_SUCCESS) {
                            if (this.ghDevice)
                                this.ghDevice.close();
                            this.ghDevice = null;
                            this.gsKseLastErrorCode = sRv;
                            return [2 /*return*/, KseDim.KSE_FAIL];
                        }
                        outabVer.value = new Array(3);
                        this.ArrayCopy(abRxData, 9, outabVer.value, 0, 3);
                        outbLifeCycle.value = abRxData[12];
                        outabChipSerial.value = new Array(8);
                        this.ArrayCopy(abRxData, 35, outabChipSerial.value, 0, 8);
                        outabSystemTitle.value = new Array(8);
                        this.ArrayCopy(abRxData, 13, outabSystemTitle.value, 0, 8);
                        outbVcType.value = abRxData[21];
                        outbMaxVcRetryCount.value = abRxData[22];
                        outsMaxChannelCount.value = (abRxData[23] << 8) | abRxData[24];
                        outsMaxKcmvpKeyCount.value = (abRxData[25] << 8) | abRxData[26];
                        outsMaxCertKeyCount.value = (abRxData[27] << 8) | abRxData[28];
                        outsMaxIoDataSize.value = (abRxData[29] << 8) | abRxData[30];
                        outiInfoFileSize.value =
                            (abRxData[31] << 24) |
                                (abRxData[32] << 16) |
                                (abRxData[33] << 8) |
                                abRxData[34];
                        this.gsKsePower = this.KSE_POWER_ON;
                        return [2 /*return*/, sRv];
                    case 2:
                        e_9 = _a.sent();
                        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNKNOWN_ERR;
                        return [2 /*return*/, KseDim.KSE_FAIL];
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
    //////////////////////////////////////////////////////////////////////////////
    //// Type Definitions ////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////
    //// Constants ///////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////
    //// Public ------------------------------------------------------------------
    //// KseDim //////////////////////////////////////////////////////////////////
    KseDim.MAX_CHANNEL_COUNT = 6;
    KseDim.MAX_KCMVP_KEY_COUNT = 64;
    KseDim.MAX_CERT_KEY_COUNT = 1024;
    KseDim.MAX_IO_DATA_SIZE = 2944;
    KseDim.MAX_INFO_FILE_SIZE = 1048576;
    KseDim.MAX_CTRL_DATA_SIZE = 128;
    KseDim.MAX_TRANSCEIVE_SIZE = KseDim.MAX_IO_DATA_SIZE + KseDim.MAX_CTRL_DATA_SIZE; // 3,072.
    //// KSE /////////////////////////////////////////////////////////////////////
    KseDim.KSE_TRUE = 1;
    KseDim.KSE_FALSE = 0;
    KseDim.NOT_USED = 0;
    KseDim.LC_MANUFACTURED = 0xff;
    KseDim.LC_ISSUED = 0x00;
    KseDim.LC_TERMINATED = 0xee;
    KseDim.VC_DISABLED = 0xff;
    KseDim.VC_TYPE_0 = 0x00;
    KseDim.VC_TYPE_1 = 0x01;
    KseDim.VC_TYPE_2 = 0x02;
    KseDim.VC_TYPE_3 = 0x03;
    KseDim.VC_TYPE_4 = 0x04;
    KseDim.VC_INFINITE = 0x00;
    KseDim.CLEAR_ALL = 0x00;
    KseDim.CLEAR_ISSUE_DATA_ONLY = 0x01;
    //// KCMVP ///////////////////////////////////////////////////////////////////
    KseDim.KCMVP_DES_KEY = 0x20;
    KseDim.KCMVP_TDES_KEY = 0x30;
    KseDim.KCMVP_AES128_KEY = 0x40;
    KseDim.KCMVP_AES192_KEY = 0x41;
    KseDim.KCMVP_AES256_KEY = 0x42;
    KseDim.KCMVP_ARIA128_KEY = 0x50;
    KseDim.KCMVP_ARIA192_KEY = 0x51;
    KseDim.KCMVP_ARIA256_KEY = 0x52;
    KseDim.KCMVP_HMAC_KEY = 0x70;
    KseDim.KCMVP_ECDSA_KEYPAIR = 0x80;
    KseDim.KCMVP_ECDSA_PRI_KEY = 0x81;
    KseDim.KCMVP_ECDSA_PUB_KEY = 0x82;
    KseDim.KCMVP_ECDH_KEYPAIR = 0x90;
    KseDim.KCMVP_ECDH_PRI_KEY = 0x91;
    KseDim.KCMVP_ECDH_PUB_KEY = 0x92;
    KseDim.KCMVP_KEY_INDEX = 0x0000;
    KseDim.CERT_KEY_INDEX = 0x8000;
    KseDim.AMI_KEY_INDEX = 0x8000;
    KseDim.ENCRYPT = 0;
    KseDim.DECRYPT = 1;
    //// Cert ////////////////////////////////////////////////////////////////////
    //// KSETLS //////////////////////////////////////////////////////////////////
    KseDim.KSETLS_MODE_TLS = 0;
    KseDim.KSETLS_MODE_DTLS = 1;
    KseDim.KSETLS_CLIENT = 0;
    KseDim.KSETLS_SERVER = 1;
    KseDim.NO_USE = 0xffff;
    KseDim.NONE = 0x00;
    KseDim.OPP_CERT = 0x01; // Opponent Certificate.
    KseDim.OPP_PUB_KEY = 0x02; // Opponent Public Key.
    KseDim.EKM = 0x04; // Exported Keying Material.
    KseDim.SESSION = 0x08; // Session ID.
    KseDim.KSETLS_TIMEOUT = 30000; // 30000ms, 30 seconds.
    KseDim.KSETLS_DATA_HANDSHAKE = 0;
    KseDim.KSETLS_DATA_ENCRYPT = 1;
    KseDim.KSETLS_DATA_CLOSE = 2;
    KseDim.KSETLS_DATA_WARNING = 3;
    KseDim.KSETLS_FULL_HANDSHAKE = 0;
    KseDim.KSETLS_ABBR_HANDSHAKE = 1;
    KseDim.DTLS_TIMEOUT_MIN = 8000; //  8000 ms,  8 sec.
    KseDim.DTLS_TIMEOUT_MAX = 60000; // 60000 ms, 60 sec.
    // [RFC 6347 P.24] Implementations SHOULD use an initial timer value of
    // 1 second (the minimum defined in RFC 6298 [RFC6298]) and double the
    // value at each retransmission, up to no less than the RFC 6298 maximum
    // of 60 seconds.
    // : kseTLS recommends the minimum time out to 8 seconds for minimum
    //   retransmission.
    KseDim.MAX_UDP_DATAGRAM_LEN = 1500;
    //// DIM /////////////////////////////////////////////////////////////////////
    KseDim.MAX_DRONE_ID_COUNT = 8;
    KseDim.DID_ONLY = 0x00;
    KseDim.DID_ECDSA = 0x01;
    KseDim.DID_HMAC = 0x02;
    //// KSE API Error Codes /////////////////////////////////////////////////////
    KseDim.ICC_SUCCESS = 0x0000;
    KseDim.ICC_FAIL = -0x8000; // 0x8000
    KseDim.ICC_FAIL_WRONG_INPUT = -0x0100; // 0xFF00
    KseDim.ICC_FAIL_NOT_SUPPORTED = -0x0101; // 0xFEFF
    KseDim.ICC_FAIL_NOT_POWERED_ON = -0x0102; // 0xFEFE
    KseDim.ICC_FAIL_ALREADY_POWERED_ON = -0x0103; // 0xFEFD
    KseDim.ICC_FAIL_ATR = -0x0104; // 0xFEFC
    KseDim.ICC_FAIL_PPS = -0x0105; // 0xFEFB
    KseDim.ICC_FAIL_TX = -0x0106; // 0xFEFA
    KseDim.ICC_FAIL_RX = -0x0107; // 0xFEF9
    KseDim.ICC_FAIL_CHAINING = -0x0108; // 0xFEF8
    KseDim.ICC_FAIL_APDU_FORMAT = -0x0109; // 0xFEF7
    KseDim.ICC_FAIL_UNKNOWN_CMD = -0x010a; // 0xFEF6
    KseDim.ICC_FAIL_STATE = -0x010b; // 0xFEF5
    KseDim.ICC_FAIL_CODE_VERIFY = -0x010c; // 0xFEF4
    KseDim.ICC_FAIL_CRYPTO_VERIFY = -0x010d; // 0xFEF3
    KseDim.ICC_FAIL_CERT_VERIFY = -0x010e; // 0xFEF2
    KseDim.ICC_FAIL_FLASH = -0x010f; // 0xFEF1
    KseDim.KSE_SUCCESS = 0x0000;
    KseDim.KSE_FAIL = -0x8000; // 0x8000
    KseDim.KSE_FAIL_WRONG_INPUT = -0x0200; // 0xFE00
    KseDim.KSE_FAIL_NOT_SUPPORTED = -0x0201; // 0xFDFF
    KseDim.KSE_FAIL_NOT_POWERED_ON = -0x0202; // 0xFDFE
    KseDim.KSE_FAIL_ALREADY_POWERED_ON = -0x0203; // 0xFDFD
    KseDim.KSE_FAIL_ATR = -0x0204; // 0xFDFC
    KseDim.KSE_FAIL_PPS = -0x0205; // 0xFDFB
    KseDim.KSE_FAIL_TX = -0x0206; // 0xFDFA
    KseDim.KSE_FAIL_RX = -0x0207; // 0xFDF9
    KseDim.KSE_FAIL_CHAINING = -0x0208; // 0xFDF8
    KseDim.KSE_FAIL_APDU_FORMAT = -0x0209; // 0xFDF7
    KseDim.KSE_FAIL_UNKNOWN_CMD = -0x020a; // 0xFDF6
    KseDim.KSE_FAIL_STATE = -0x020b; // 0xFDF5
    KseDim.KSE_FAIL_CODE_VERIFY = -0x020c; // 0xFDF4
    KseDim.KSE_FAIL_CRYPTO_VERIFY = -0x020d; // 0xFDF3
    KseDim.KSE_FAIL_CERT_VERIFY = -0x020e; // 0xFDF2
    KseDim.KSE_FAIL_FLASH = -0x020f; // 0xFDF1
    KseDim.KSE_FAIL_SPI_SEND_DATA = -0x0213; // 0xFDED
    KseDim.KSE_FAIL_SPI_RECV_DATA = -0x0214; // 0xFDEC
    KseDim.KSE_FAIL_SPI_TIME_OUT = -0x0215; // 0xFDEB
    KseDim.KSE_FAIL_UNKNOWN_ERR = -0x0210; // 0xFDF0
    KseDim.KSE_FAIL_USB_INIT = -0x0300; // 0xFD00
    KseDim.KSE_FAIL_USB_NO_DEVICES = -0x0301; // 0xFCFF
    KseDim.KSE_FAIL_USB_DEVICE_OPEN = -0x0302; // 0xFCFE
    KseDim.KSE_FAIL_USB_DETACH_KERNEL_DRIVER = -0x0303; // 0xFCFD
    KseDim.KSE_FAIL_USB_CLAIM_INTERFACE = -0x0304; // 0xFCFC
    KseDim.KSE_FAIL_USB_SEND_REPORT = -0x0305; // 0xFCFB
    KseDim.KSE_FAIL_USB_RECV_REPORT = -0x0306; // 0xFCFA
    KseDim.KSE_FAIL_NOT_FOUND = -0x0307; // 0xFCF9
    KseDim.KSE_FAIL_UNEXPECTED_RESP = -0x0308; // 0xFCF8
    KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN = -0x0309; // 0xFCF7
    KseDim.KSE_FAIL_RECV_BUF_OVERFLOW = -0x030a; // 0xFCF6
    KseDim.KSE_FAIL_NO_USB_PERMISSION = -0x030b; // 0xFCF5
    KseDim.KSETLS_FRAGMENT_RECORD = 0x0004;
    // Fragment record.
    KseDim.KSETLS_HELLO_VERIFY_REQUEST = 0x0003;
    // Hello verify requested.
    KseDim.KSETLS_HANDSHAKE_IN_PROGRESS = 0x0002;
    // Handshake is not completed yet.
    KseDim.KSETLS_HANDSHAKE_DONE = 0x0001;
    // Handshake done.
    KseDim.KSETLS_SUCCESS = 0x0000;
    // Success.
    KseDim.KSETLS_FAIL = -0x0001;
    // Fail.
    KseDim.KSETLS_ERR_NET_CONFIG = -0x0040;
    // Failed to get ip address! Please check your network configuration.
    KseDim.KSETLS_ERR_NET_SOCKET_FAILED = -0x0042;
    // Failed to open a socket.
    KseDim.KSETLS_ERR_NET_CONNECT_FAILED = -0x0044;
    // The connection to the given server:port failed.
    KseDim.KSETLS_ERR_NET_BIND_FAILED = -0x0046;
    // Binding of the socket failed.
    KseDim.KSETLS_ERR_NET_LISTEN_FAILED = -0x0048;
    // Could not listen on the socket.
    KseDim.KSETLS_ERR_NET_ACCEPT_FAILED = -0x004a;
    // Could not accept the incoming connection.
    KseDim.KSETLS_ERR_NET_RECV_FAILED = -0x004c;
    // Reading information from the socket failed.
    KseDim.KSETLS_ERR_NET_SEND_FAILED = -0x004e;
    // Sending information through the socket failed.
    KseDim.KSETLS_ERR_NET_CONN_RESET = -0x0050;
    // Connection was reset by peer.
    KseDim.KSETLS_ERR_NET_UNKNOWN_HOST = -0x0052;
    // Failed to get an IP address for the given hostname.
    KseDim.KSETLS_ERR_NET_BUFFER_TOO_SMALL = -0x0043;
    // Buffer is too small to hold the data.
    KseDim.KSETLS_ERR_NET_INVALID_CONTEXT = -0x0045;
    // The context is invalid, eg because it was free()ed.
    KseDim.KSETLS_ERR_NET_POLL_FAILED = -0x0047;
    // Polling the net context failed.
    KseDim.KSETLS_ERR_NET_BAD_INPUT_DATA = -0x0049;
    // Input invalid.
    KseDim.KSETLS_ERR_TLS_FEATURE_UNAVAILABLE = -0x7080;
    // The requested feature is not available.
    KseDim.KSETLS_ERR_TLS_BAD_INPUT_DATA = -0x7100;
    // Bad input parameters to function.
    KseDim.KSETLS_ERR_TLS_INVALID_MAC = -0x7180;
    // Verification of the message MAC failed.
    KseDim.KSETLS_ERR_TLS_INVALID_RECORD = -0x7200;
    // An invalid SSL record was received.
    KseDim.KSETLS_ERR_TLS_CONN_EOF = -0x7280;
    // The connection indicated an EOF.
    KseDim.KSETLS_ERR_TLS_UNKNOWN_CIPHER = -0x7300;
    // An unknown cipher was received.
    KseDim.KSETLS_ERR_TLS_NO_CIPHER_CHOSEN = -0x7380;
    // The server has no ciphersuites in common with the client.
    KseDim.KSETLS_ERR_TLS_NO_RNG = -0x7400;
    // No RNG was provided to the SSL module.
    KseDim.KSETLS_ERR_TLS_NO_CLIENT_CERTIFICATE = -0x7480;
    // No client certification received from the client,
    // but required by the authentication mode.
    KseDim.KSETLS_ERR_TLS_CERTIFICATE_TOO_LARGE = -0x7500;
    // Our own certificate(s) is/are too large to send in an SSL message.
    KseDim.KSETLS_ERR_TLS_CERTIFICATE_REQUIRED = -0x7580;
    // The own certificate is not set, but needed by the server.
    KseDim.KSETLS_ERR_TLS_PRIVATE_KEY_REQUIRED = -0x7600;
    // The own private key or pre-shared key is not set, but needed.
    KseDim.KSETLS_ERR_TLS_CA_CHAIN_REQUIRED = -0x7680;
    // No CA Chain is set, but required to operate.
    KseDim.KSETLS_ERR_TLS_UNEXPECTED_MESSAGE = -0x7700;
    // An unexpected message was received from our peer.
    KseDim.KSETLS_ERR_TLS_FATAL_ALERT_MESSAGE = -0x7780;
    // A fatal alert message was received from our peer.
    KseDim.KSETLS_ERR_TLS_PEER_VERIFY_FAILED = -0x7800;
    // Verification of our peer failed.
    KseDim.KSETLS_ERR_TLS_PEER_CLOSE_NOTIFY = -0x7880;
    // The peer notified us that the connection is going
    // to be closed.
    KseDim.KSETLS_ERR_TLS_BAD_HS_CLIENT_HELLO = -0x7900;
    // Processing of the ClientHello handshake message failed.
    KseDim.KSETLS_ERR_TLS_BAD_HS_SERVER_HELLO = -0x7980;
    // Processing of the ServerHello handshake message
    // failed.
    KseDim.KSETLS_ERR_TLS_BAD_HS_CERTIFICATE = -0x7a00;
    // Processing of the Certificate handshake message failed.
    KseDim.KSETLS_ERR_TLS_BAD_HS_CERTIFICATE_REQUEST = -0x7a80;
    // Processing of the CertificateRequest handshake message failed.
    KseDim.KSETLS_ERR_TLS_BAD_HS_SERVER_KEY_EXCHANGE = -0x7b00;
    // Processing of the ServerKeyExchange handshake message failed.
    KseDim.KSETLS_ERR_TLS_BAD_HS_SERVER_HELLO_DONE = -0x7b80;
    // Processing of the ServerHelloDone handshake
    // message failed.
    KseDim.KSETLS_ERR_TLS_BAD_HS_CLIENT_KEY_EXCHANGE = -0x7c00;
    // Processing of the ClientKeyExchange handshake message failed.
    KseDim.KSETLS_ERR_TLS_BAD_HS_CLIENT_KEY_EXCHANGE_RP = -0x7c80;
    // Processing of the ClientKeyExchange handshake message failed
    // in DHM / ECDH Read Public.
    KseDim.KSETLS_ERR_TLS_BAD_HS_CLIENT_KEY_EXCHANGE_CS = -0x7d00;
    // Processing of the ClientKeyExchange handshake
    // message failed in DHM / ECDH Calculate Secret.
    KseDim.KSETLS_ERR_TLS_BAD_HS_CERTIFICATE_VERIFY = -0x7d80;
    // Processing of the CertificateVerify handshake message failed.
    KseDim.KSETLS_ERR_TLS_BAD_HS_CHANGE_CIPHER_SPEC = -0x7e00;
    // Processing of the ChangeCipherSpec handshake message failed.
    KseDim.KSETLS_ERR_TLS_BAD_HS_FINISHED = -0x7e80;
    // Processing of the Finished handshake message failed.
    KseDim.KSETLS_ERR_TLS_ALLOC_FAILED = -0x7f00;
    // Memory allocation failed.
    KseDim.KSETLS_ERR_TLS_HW_ACCEL_FAILED = -0x7f80;
    // Hardware acceleration function returned with error.
    KseDim.KSETLS_ERR_TLS_HW_ACCEL_FALLTHROUGH = -0x6f80;
    // Hardware acceleration function skipped / left alone data.
    KseDim.KSETLS_ERR_TLS_COMPRESSION_FAILED = -0x6f00;
    // Processing of the compression / decompression failed.
    KseDim.KSETLS_ERR_TLS_BAD_HS_PROTOCOL_VERSION = -0x6e80;
    // Handshake protocol not within min/max boundaries.
    KseDim.KSETLS_ERR_TLS_BAD_HS_NEW_SESSION_TICKET = -0x6e00;
    // Processing of the NewSessionTicket handshake message failed.
    KseDim.KSETLS_ERR_TLS_SESSION_TICKET_EXPIRED = -0x6d80;
    // Session ticket has expired.
    KseDim.KSETLS_ERR_TLS_PK_TYPE_MISMATCH = -0x6d00;
    // Public key type mismatch (eg, asked for RSA key
    // exchange and presented EC key).
    KseDim.KSETLS_ERR_TLS_UNKNOWN_IDENTITY = -0x6c80;
    // Unknown identity received (eg, PSK identity).
    KseDim.KSETLS_ERR_TLS_INTERNAL_ERROR = -0x6c00;
    // Internal error (eg, unexpected failure in lower-level module).
    KseDim.KSETLS_ERR_TLS_COUNTER_WRAPPING = -0x6b80;
    // A counter would wrap (eg, too many messages exchanged).
    KseDim.KSETLS_ERR_TLS_WAITING_SERVER_HELLO_RENEGO = -0x6b00;
    // Unexpected message at ServerHello in renegotiation.
    KseDim.KSETLS_ERR_TLS_HELLO_VERIFY_REQUIRED = -0x6a80;
    // DTLS client must retry for hello verification.
    KseDim.KSETLS_ERR_TLS_BUFFER_TOO_SMALL = -0x6a00;
    // A buffer is too small to receive or write a message.
    KseDim.KSETLS_ERR_TLS_NO_USABLE_CIPHERSUITE = -0x6980;
    // None of the common ciphersuites is usable (eg, no suitable certificate,
    // see debug messages).
    KseDim.KSETLS_ERR_TLS_WANT_READ = -0x6900;
    // No data of requested type currently available on underlying transport.
    KseDim.KSETLS_ERR_TLS_WANT_WRITE = -0x6880;
    // Connection requires a write call.
    KseDim.KSETLS_ERR_TLS_TIMEOUT = -0x6800;
    // The operation timed out.
    KseDim.KSETLS_ERR_TLS_CLIENT_RECONNECT = -0x6780;
    // The client initiated a reconnect from the same port.
    KseDim.KSETLS_ERR_TLS_UNEXPECTED_RECORD = -0x6700;
    // Record header looks valid but is not expected.
    KseDim.KSETLS_ERR_TLS_NON_FATAL = -0x6680;
    // The alert message received indicates a non-fatal error.
    KseDim.KSETLS_ERR_TLS_INVALID_VERIFY_HASH = -0x6600;
    // Couldn't set the hash for verifying CertificateVerify.
    KseDim.KSETLS_ERR_TLS_CONTINUE_PROCESSING = -0x6580;
    // Internal-only message signaling that further message-processing
    // should be done.
    KseDim.KSETLS_ERR_TLS_ASYNC_IN_PROGRESS = -0x6500;
    // The asynchronous operation is not completed yet.
    KseDim.KSETLS_ERR_TLS_EARLY_MESSAGE = -0x6480;
    // Internal-only message signaling that a message
    // arrived early.
    KseDim.KSETLS_ERR_TLS_CRYPTO_IN_PROGRESS = -0x7000;
    // A cryptographic operation failure in progress.
    //// Debug ///////////////////////////////////////////////////////////////////
    KseDim.SENT = 0;
    KseDim.RECV = 1;
    return KseDim;
}());
exports.default = KseDim;
//# sourceMappingURL=KseDim.js.map