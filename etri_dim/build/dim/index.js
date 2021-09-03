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
var KseDim_1 = __importDefault(require("./KseDim"));
var OutObject_1 = require("./OutObject");
var Constants_1 = require("./Constants");
var Converter_1 = require("./Converter");
var Topics_1 = require("./Topics");
var DEV_CERT_INDEX = 2;
var SUB_CA_CERT_INDEX = 1;
var ROOT_CA_CERT_INDEX = 0;
var CONNECTION_TIMEOUT = 30000;
var TX_WAIT_TIME = 200;
var INTERVAL = 50;
var req_enc_count = 0;
var req_sig_count = 0;
var DimClientHandler = /** @class */ (function () {
    //// Constructor ///////////////////////////////////////////////////////////////
    function DimClientHandler(mqttClient) {
        var _this = this;
        this.channelCnt = 0;
        this.channelInfo = {};
        this.descriptors = new Array(KseDim_1.default.MAX_CHANNEL_COUNT).fill(null);
        this.tlsClientConnectBuffer = {
            resolve: undefined,
            requests: [],
        };
        this.tlsHandshakeBuffer = {
            resolve: undefined,
            requests: [],
        };
        this.tlsEncryptBuffer = {
            resolve: undefined,
            requests: [],
        };
        this.tlsConnectResolver = function (iSocketDesc, resolve, timeout) {
            if (_this.tlsClientConnectBuffer.requests &&
                _this.tlsClientConnectBuffer.requests.length > 0) {
                // Check if any data is received with the session id.
                var index = _this.tlsClientConnectBuffer.requests.findIndex(function (request) {
                    return request.sessionId === iSocketDesc;
                });
                if (index < 0) {
                    if (timeout <= 0) {
                        console.log("Connection request timed out.[0]");
                        resolve(Constants_1.FAILURE);
                        return;
                    }
                    else {
                        setTimeout(function () {
                            _this.tlsConnectResolver(iSocketDesc, resolve, timeout - INTERVAL);
                        }, INTERVAL);
                        return;
                    }
                }
                try {
                    var result = (0, Converter_1.hexStrToByteArr)(_this.tlsClientConnectBuffer.requests[index].data);
                    _this.tlsClientConnectBuffer.requests.splice(index, 1);
                    if (result[0] === Constants_1.SUCCESS)
                        resolve(Constants_1.SUCCESS);
                    else
                        resolve(Constants_1.FAILURE);
                }
                catch (e) {
                    _this.tlsClientConnectBuffer.requests.splice(index, 1);
                    resolve(Constants_1.FAILURE);
                }
                return;
            }
            else {
                if (timeout <= 0) {
                    console.log("Connection request timed out.[1]");
                    resolve(Constants_1.FAILURE);
                    return;
                }
                else {
                    setTimeout(function () {
                        _this.tlsConnectResolver(iSocketDesc, resolve, timeout - INTERVAL);
                    }, INTERVAL);
                    return;
                }
            }
        };
        this.connect = function (mqttClient, iSocketDesc, timeout) { return __awaiter(_this, void 0, void 0, function () {
            var _this = this;
            return __generator(this, function (_a) {
                return [2 /*return*/, new Promise(function (resolve) {
                        try {
                            var request = {
                                id: 1,
                                clientId: "none",
                                method: "MQTT",
                                type: Constants_1.TLS_CONNECT,
                                sessionId: iSocketDesc,
                                data: "",
                            };
                            var message = JSON.stringify(request);
                            mqttClient.publish(Topics_1.TOPIC_MUV_DATA_LIB_SEC_REQ_AUTH, message);
                            _this.tlsConnectResolver(iSocketDesc, resolve, timeout);
                            return;
                        }
                        catch (e) {
                            resolve(Constants_1.FAILURE);
                            return;
                        }
                    })];
            });
        }); };
        this.close = function (clientId, iSocketDesc) { return __awaiter(_this, void 0, void 0, function () {
            var _this = this;
            return __generator(this, function (_a) {
                return [2 /*return*/, new Promise(function (resolve) {
                        try {
                            var request = {
                                id: 1,
                                clientId: clientId,
                                method: "MQTT",
                                type: Constants_1.TLS_CLOSE,
                                sessionId: iSocketDesc,
                                data: "",
                            };
                            var message = JSON.stringify(request);
                            _this.mqttClient.publish(Topics_1.TOPIC_MUV_DATA_LIB_SEC_REQ_AUTH, message);
                            resolve(Constants_1.SUCCESS);
                            return;
                        }
                        catch (e) {
                            resolve(Constants_1.FAILURE);
                            return;
                        }
                    })];
            });
        }); };
        ////////////////////////////////////////////////////////////////////////////////
        //// KSE TLS Handler  //////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        this.tlsHandshakeReadResolver = function (clientId, bCh, resolve, timeout) {
            // Get socket descriptor.
            var iSocketDesc = _this.descriptors[bCh];
            if (iSocketDesc === null || iSocketDesc === undefined) {
                console.log("There is no descriptor for channel " + bCh + ". [1]");
                resolve(null);
                return;
            }
            if (_this.tlsHandshakeBuffer.requests &&
                _this.tlsHandshakeBuffer.requests.length > 0) {
                // Check if any data is received with the session id.
                var index = _this.tlsHandshakeBuffer.requests.findIndex(function (request) {
                    return request.sessionId === iSocketDesc;
                });
                if (index < 0) {
                    if (timeout <= 0) {
                        resolve(null);
                        return;
                    }
                    else {
                        setTimeout(function () {
                            _this.tlsHandshakeReadResolver(clientId, bCh, resolve, timeout - INTERVAL);
                        }, INTERVAL);
                        return;
                    }
                }
                try {
                    var result = (0, Converter_1.hexStrToByteArr)(_this.tlsHandshakeBuffer.requests[index].data);
                    _this.tlsHandshakeBuffer.requests.splice(index, 1);
                    resolve(result);
                }
                catch (e) {
                    _this.tlsHandshakeBuffer.requests.splice(index, 1);
                    resolve(null);
                }
                return;
            }
            else {
                if (timeout <= 0) {
                    resolve(null);
                    return;
                }
                else {
                    setTimeout(function () {
                        _this.tlsHandshakeReadResolver(clientId, bCh, resolve, timeout - INTERVAL);
                    }, INTERVAL);
                    return;
                }
            }
        };
        this.tlsEncryptReadResolver = function (clientId, bCh, resolve, timeout) {
            // Get socket descriptor.
            var iSocketDesc = _this.descriptors[bCh];
            if (iSocketDesc === null || iSocketDesc === undefined) {
                console.log("There is no descriptor for channel " + bCh + ". [2]");
                resolve(null);
                return;
            }
            if (_this.tlsEncryptBuffer.requests &&
                _this.tlsEncryptBuffer.requests.length > 0) {
                // check if any data is received with the session id.
                var index = _this.tlsEncryptBuffer.requests.findIndex(function (request) {
                    return request.sessionId === iSocketDesc;
                });
                if (index < 0) {
                    if (timeout <= 0) {
                        resolve(null);
                        return;
                    }
                    else {
                        setTimeout(function () {
                            _this.tlsEncryptReadResolver(clientId, bCh, resolve, timeout - INTERVAL);
                        }, INTERVAL);
                        return;
                    }
                }
                try {
                    var result = (0, Converter_1.hexStrToByteArr)(_this.tlsEncryptBuffer.requests[index].data);
                    _this.tlsEncryptBuffer.requests.splice(index, 1);
                    resolve(result);
                }
                catch (e) {
                    _this.tlsEncryptBuffer.requests.splice(index, 1);
                    resolve(null);
                }
                return;
            }
            else {
                if (timeout <= 0) {
                    resolve(null);
                    return;
                }
                else {
                    setTimeout(function () {
                        _this.tlsEncryptReadResolver(clientId, bCh, resolve, timeout - INTERVAL);
                    }, INTERVAL);
                    return;
                }
            }
        };
        this.tlsWriteHandlerImpl = {
            write: function (iDataType, clientId, bCh, abData) {
                return new Promise(function (resolve) {
                    try {
                        // Get socket descriptor.
                        var iSocketDesc = _this.descriptors[bCh];
                        if (iSocketDesc === null || iSocketDesc === undefined) {
                            console.log("There is no descriptor for channel " + bCh + ". [3]");
                            resolve(-1);
                            return;
                        }
                        switch (iDataType) {
                            case KseDim_1.default.KSETLS_DATA_HANDSHAKE: {
                                var request = {
                                    id: 0,
                                    clientId: clientId,
                                    method: "MQTT",
                                    type: Constants_1.TLS_HANDSHAKE,
                                    sessionId: iSocketDesc,
                                    data: (0, Converter_1.byteArrToHexStr)(abData),
                                };
                                var message = JSON.stringify(request);
                                _this.mqttClient.publish(Topics_1.TOPIC_MUV_DATA_LIB_SEC_REQ_AUTH, message);
                                setTimeout(function () {
                                    resolve(abData.length);
                                }, TX_WAIT_TIME);
                                return;
                            }
                            case KseDim_1.default.KSETLS_DATA_ENCRYPT: {
                                var request = {
                                    id: 1,
                                    clientId: clientId,
                                    method: "MQTT",
                                    type: Constants_1.TLS_DECRYPT,
                                    sessionId: iSocketDesc,
                                    data: (0, Converter_1.byteArrToHexStr)(abData),
                                };
                                var message = JSON.stringify(request);
                                _this.mqttClient.publish(Topics_1.TOPIC_MUV_DATA_LIB_SEC_REQ_AUTH, message);
                                setTimeout(function () {
                                    resolve(abData.length);
                                }, TX_WAIT_TIME);
                                return;
                            }
                            default:
                                resolve(Constants_1.FAILURE);
                                return;
                        }
                    }
                    catch (e) {
                        resolve(Constants_1.FAILURE);
                        return;
                    }
                });
            },
        };
        this.tlsReadHandlerImpl = {
            read: function (iDataType, clientId, bCh, timeout) {
                return new Promise(function (resolve) {
                    try {
                        switch (iDataType) {
                            case KseDim_1.default.KSETLS_DATA_HANDSHAKE: {
                                _this.tlsHandshakeReadResolver(clientId, bCh, resolve, timeout);
                                break;
                            }
                            case KseDim_1.default.KSETLS_DATA_ENCRYPT: {
                                _this.tlsEncryptReadResolver(clientId, bCh, resolve, timeout);
                                break;
                            }
                            default:
                                return;
                        }
                        return;
                    }
                    catch (e) {
                        resolve(null);
                        return;
                    }
                });
            },
        };
        this.gKse = new KseDim_1.default(this.tlsReadHandlerImpl, this.tlsWriteHandlerImpl);
        this.giSocketDesc = -1;
        ////////////////////////////////////////////////////////////////////////////////
        //// KSE Operations  ///////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////
        this.startTlsRead = function (clientId, iSocketDesc) { return __awaiter(_this, void 0, void 0, function () {
            var bCh, Kse, abBuffer, e_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        bCh = this.channelInfo[iSocketDesc];
                        if (bCh === null || bCh === undefined) {
                            console.log("A channel is not found with the socket descriptor(" + iSocketDesc + "). [1]");
                            return [2 /*return*/];
                        }
                        console.log("");
                        console.log("Start TLS decryption...");
                        Kse = this.gKse;
                        abBuffer = null;
                        return [4 /*yield*/, Kse.KsetlsTlsRead(clientId, bCh)];
                    case 1:
                        // Read TLS application data.
                        abBuffer = _a.sent();
                        if (abBuffer) {
                            console.log("KsetlsTlsRead() : Success...");
                            console.log("Decrypted message: ", Buffer.from(abBuffer).toString("utf8"));
                        }
                        else {
                            Kse.DebugPrintErrStr("KsetlsTlsRead()");
                            return [2 /*return*/];
                        }
                        return [2 /*return*/];
                    case 2:
                        e_1 = _a.sent();
                        console.log("Client TLS reading data has failed.");
                        return [2 /*return*/];
                    case 3: return [2 /*return*/];
                }
            });
        }); };
        this.startTlsHandshake = function () { return __awaiter(_this, void 0, void 0, function () {
            var bCh, Kse, bHandshakeType, sRv, iSocketDesc, flag, e_2, e_3;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 12, , 13]);
                        if (this.channelCnt >= KseDim_1.default.MAX_CHANNEL_COUNT) {
                            console.log("Max channel count(" + KseDim_1.default.MAX_CHANNEL_COUNT + ") has been reached. Close other channel before opening a new channel.");
                            return [2 /*return*/];
                        }
                        bCh = this.descriptors.findIndex(function (descriptor) {
                            return descriptor === null || descriptor === undefined;
                        });
                        Kse = this.gKse;
                        bHandshakeType = KseDim_1.default.KSETLS_FULL_HANDSHAKE;
                        sRv = KseDim_1.default.KSE_SUCCESS;
                        // Connect to server.
                        console.log("");
                        iSocketDesc = new Date().getTime() + (0, Converter_1.getRandomInt)(1000000);
                        this.descriptors[bCh] = iSocketDesc;
                        this.channelInfo[iSocketDesc] = bCh;
                        this.channelCnt++;
                        flag = true;
                        _a.label = 1;
                    case 1:
                        if (!flag) return [3 /*break*/, 6];
                        console.log("The client is trying to connect to the server...");
                        _a.label = 2;
                    case 2:
                        _a.trys.push([2, 4, , 5]);
                        return [4 /*yield*/, this.connect(this.mqttClient, iSocketDesc, CONNECTION_TIMEOUT)];
                    case 3:
                        sRv = _a.sent();
                        if (sRv !== Constants_1.SUCCESS) {
                            console.log("Server connection failed.");
                            return [3 /*break*/, 1];
                        }
                        return [3 /*break*/, 5];
                    case 4:
                        e_2 = _a.sent();
                        console.log("Server connection failed.");
                        return [3 /*break*/, 1];
                    case 5: return [3 /*break*/, 6];
                    case 6:
                        // Open kseTLS.
                        console.log("  * Open kseTLS(TLS Client) with session " + iSocketDesc + ".");
                        return [4 /*yield*/, Kse.KsetlsOpen(bCh, KseDim_1.default.KSETLS_MODE_TLS, KseDim_1.default.KSETLS_CLIENT, DEV_CERT_INDEX, SUB_CA_CERT_INDEX, ROOT_CA_CERT_INDEX, KseDim_1.default.NO_USE, KseDim_1.default.NO_USE, KseDim_1.default.NO_USE, KseDim_1.default.NO_USE)];
                    case 7:
                        sRv = _a.sent();
                        if (sRv === KseDim_1.default.KSE_SUCCESS) {
                            console.log("KsetlsOpen() : Success...");
                        }
                        else {
                            Kse.DebugPrintErrStr("KsetlsOpen()");
                            return [2 /*return*/];
                        }
                        // Handshake.
                        if (bHandshakeType === KseDim_1.default.KSETLS_FULL_HANDSHAKE)
                            console.log("  * Performing the TLS full handshake...");
                        else
                            console.log("  * Performing the TLS abbreviated handshake...");
                        return [4 /*yield*/, Kse.KsetlsTlsClientHandshake("none", bCh, bHandshakeType)];
                    case 8:
                        sRv = _a.sent();
                        if (!(sRv === KseDim_1.default.KSE_SUCCESS)) return [3 /*break*/, 9];
                        console.log("KsetlsTlsClientHandshake() : Success...");
                        this.giSocketDesc = iSocketDesc;
                        return [3 /*break*/, 11];
                    case 9:
                        Kse.DebugPrintErrStr("KsetlsTlsClientHandshake()");
                        this.descriptors[bCh] = null;
                        delete this.channelInfo[iSocketDesc];
                        this.channelCnt--;
                        return [4 /*yield*/, Kse.KsetlsClose(bCh)];
                    case 10:
                        sRv = _a.sent();
                        this.giSocketDesc = -1;
                        return [2 /*return*/];
                    case 11:
                        this.mqttClient.publish(Topics_1.TOPIC_MUV_DATA_LIB_SEC_REQ_READY, "");
                        return [2 /*return*/];
                    case 12:
                        e_3 = _a.sent();
                        console.log("Client TLS handshake has failed.");
                        return [2 /*return*/];
                    case 13: return [2 /*return*/];
                }
            });
        }); };
        this.startClient = function () { return __awaiter(_this, void 0, void 0, function () {
            var Kse, sRv, outabVer, outabChipSerial, outabSystemTitle, outbLifeCycle, outbVcType, outbMaxVcRetryCount, outsMaxChannelCount, outsMaxKcmvpKeyCount, outsMaxCertKeyCount, outsMaxIoDataSize, outiInfoFileSize, abManufacturer, e_4;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 3, , 4]);
                        console.log("");
                        console.log("Start the client...");
                        console.log("");
                        Kse = this.gKse;
                        sRv = KseDim_1.default.KSE_SUCCESS;
                        // KSE debug print enable.
                        Kse.gfEnableDebugPrint = true;
                        outabVer = new OutObject_1.OutByteArray();
                        outabChipSerial = new OutObject_1.OutByteArray();
                        outabSystemTitle = new OutObject_1.OutByteArray();
                        outbLifeCycle = new OutObject_1.OutByte();
                        outbVcType = new OutObject_1.OutByte();
                        outbMaxVcRetryCount = new OutObject_1.OutByte();
                        outsMaxChannelCount = new OutObject_1.OutShort();
                        outsMaxKcmvpKeyCount = new OutObject_1.OutShort();
                        outsMaxCertKeyCount = new OutObject_1.OutShort();
                        outsMaxIoDataSize = new OutObject_1.OutShort();
                        outiInfoFileSize = new OutObject_1.OutInt();
                        return [4 /*yield*/, Kse.PowerOff()];
                    case 1:
                        // Power off and Power on KSE each.
                        sRv = _a.sent();
                        return [4 /*yield*/, Kse.PowerOn(outabVer, outbLifeCycle, outabChipSerial, outabSystemTitle, outbVcType, outbMaxVcRetryCount, outsMaxChannelCount, outsMaxKcmvpKeyCount, outsMaxCertKeyCount, outsMaxIoDataSize, outiInfoFileSize)];
                    case 2:
                        sRv = _a.sent();
                        if (sRv === KseDim_1.default.KSE_SUCCESS) {
                            console.log("PowerOn() : Success...");
                        }
                        else {
                            Kse.DebugPrintErrStr("PowerOn()");
                            return [2 /*return*/];
                        }
                        console.log("");
                        console.log("  * Version          :", "" + ("0" + outabVer.value[0].toString(16)).substr(-2), "" + ("0" + outabVer.value[1].toString(16)).substr(-2), "" + ("0" + outabVer.value[2].toString(16)).substr(-2));
                        if (outbLifeCycle.value === KseDim_1.default.LC_MANUFACTURED)
                            console.log("  * Life Cycle       : MANUFACTURED");
                        else if (outbLifeCycle.value === KseDim_1.default.LC_ISSUED)
                            console.log("  * Life Cycle       : ISSUED");
                        else if (outbLifeCycle.value === KseDim_1.default.LC_TERMINATED)
                            console.log("  * Life Cycle       : TERMINATED");
                        else
                            console.log("  * Life Cycle       : Unknown");
                        abManufacturer = new Array(3);
                        Kse.ArrayCopy(outabSystemTitle.value, 0, abManufacturer, 0, 3);
                        console.log("  * System Title     :", "" + ("0" + outabSystemTitle.value[0].toString(16)).substr(-2), "" + ("0" + outabSystemTitle.value[1].toString(16)).substr(-2), "" + ("0" + outabSystemTitle.value[2].toString(16)).substr(-2), "" + ("0" + outabSystemTitle.value[3].toString(16)).substr(-2), "" + ("0" + outabSystemTitle.value[4].toString(16)).substr(-2), "" + ("0" + outabSystemTitle.value[5].toString(16)).substr(-2), "" + ("0" + outabSystemTitle.value[6].toString(16)).substr(-2), "" + ("0" + outabSystemTitle.value[7].toString(16)).substr(-2), Buffer.from(abManufacturer).toString("utf8"), "" + ("0" + outabSystemTitle.value[3].toString(16)).substr(-2), "" + ("0" + outabSystemTitle.value[4].toString(16)).substr(-2), "" + ("0" + outabSystemTitle.value[5].toString(16)).substr(-2), "" + ("0" + outabSystemTitle.value[6].toString(16)).substr(-2), "" + ("0" + outabSystemTitle.value[7].toString(16)).substr(-2));
                        if (outbVcType.value === KseDim_1.default.VC_DISABLED)
                            console.log("  * Verify code type : Disabled");
                        else if (outbVcType.value <= KseDim_1.default.VC_TYPE_4)
                            console.log("  *  Verify code type :", ("0" + outbVcType.value.toString(16)).substr(-2));
                        else
                            console.log("  *  Verify code type : Unknown");
                        console.log("  * MaxVcRetryCount  :", ("0" + outbMaxVcRetryCount.value.toString(16)).substr(-2));
                        console.log("  * MaxKcmvpKeyCount :", ("0" + outsMaxKcmvpKeyCount.value.toString(16)).substr(-2));
                        console.log("  * MaxCertKeyCount  :", ("0" + outsMaxCertKeyCount.value.toString(16)).substr(-2));
                        console.log("  * MaxIoDataSize    :", ("0" + outsMaxIoDataSize.value.toString(16)).substr(-2));
                        console.log("  * FileSize         :", ("0" + outiInfoFileSize.value.toString(16)).substr(-2));
                        console.log("");
                        /////
                        ////  insert key
                        //// {
                        ////////////////////////////////////////////////////////////////////////////
                        //// setup code start //////////////////////////////////////////////////////
                        ////////////////////////////////////////////////////////////////////////////
                        // const sKeyIndex = 0;
                        // const abD: number[] = hexStrToByteArr(
                        //   "1A6601F02373F008FD4BB3A3537A7BC28FC87BF0B4611357C89F4F5D35377D51",
                        // );
                        // const abQxQy: number[] = hexStrToByteArr(
                        //   "69A7817931DA804BFD917D20A6565435CCC8D336AB20FF2B6334CA9B54EA83ABAF017403784B08EF229AEE6C08910D9DD7278BF5C44DA4C9D9CFDAE0865679C8",
                        // );
                        // const abMsg: number[] = strToUtf8Arr(
                        //   "This is an original message to be signed from a client.",
                        // );
                        // console.log("Erase ECDSA private key.");
                        // let iRv = await Kse.KcmvpEraseKey(KseDim.KCMVP_ECDSA_PRI_KEY, sKeyIndex);
                        // if (iRv !== KseDim.KSE_SUCCESS) {
                        //   Kse.DebugPrintErrStr("KcmvpEraseKey() ECDSA private key");
                        //   return;
                        // }
                        // console.log("Put ECDSA private key.");
                        // iRv = await Kse.KcmvpPutKey(KseDim.KCMVP_ECDSA_PRI_KEY, sKeyIndex, abD);
                        // if (iRv !== KseDim.KSE_SUCCESS) {
                        //   Kse.DebugPrintErrStr("KcmvpPutKey() ECDSA private key");
                        //   return;
                        // }
                        // console.log("Erase ECDSA public key.");
                        // iRv = await Kse.KcmvpEraseKey(KseDim.KCMVP_ECDSA_PUB_KEY, sKeyIndex);
                        // if (iRv !== KseDim.KSE_SUCCESS) {
                        //   Kse.DebugPrintErrStr("KcmvpEraseKey() ECDSA private key");
                        //   return;
                        // }
                        // console.log("Put ECDSA public key.");
                        // iRv = await Kse.KcmvpPutKey(
                        //   KseDim.KCMVP_ECDSA_PUB_KEY,
                        //   sKeyIndex,
                        //   abQxQy,
                        // );
                        // if (iRv !== KseDim.KSE_SUCCESS) {
                        //   Kse.DebugPrintErrStr("KcmvpPutKey() ECDSA public key");
                        //   return;
                        // }
                        // console.log("ECDSA Sign.");
                        // const abSig: number[] | null = await Kse.KcmvpEcdsaSign(
                        //   0,
                        //   abMsg,
                        //   sKeyIndex,
                        // );
                        // if (abSig === null) {
                        //   Kse.DebugPrintErrStr("KcmvpEcdsaSign()");
                        //   return;
                        // }
                        // console.log("ECDSA Verify.");
                        // iRv = await Kse.KcmvpEcdsaVerify(0, abMsg, abSig, sKeyIndex);
                        // if (iRv !== KseDim.KSE_SUCCESS) {
                        //   Kse.DebugPrintErrStr("KcmvpEcdsaVerify()");
                        //   return;
                        // }
                        // console.log("Key setup complete.");
                        ////  } end of insert key.
                        // const outabDid: OutByteArray = new OutByteArray();
                        // const outabAuthCode: OutByteArray = new OutByteArray();
                        // const outsDidLen: OutShort = new OutShort();
                        // const sDidIndex = 0;
                        // console.log("Read Drone ID.");
                        // iRv = await Kse.DimDidRead(
                        //   outabDid,
                        //   outsDidLen,
                        //   outabAuthCode,
                        //   sDidIndex,
                        //   KseDim.DID_ECDSA,
                        //   sKeyIndex
                        // );
                        // if (iRv !== KseDim.KSE_SUCCESS) {
                        //   Kse.DebugPrintErrStr("DimDidRead()");
                        //   return;
                        // }
                        // console.log(
                        //   "  * Drone ID         :",
                        //   (outabDid.value as number[]).reduce((accum, bDid: number): string => {
                        //     accum += String.fromCharCode(bDid);
                        //     return accum;
                        //   }, "")
                        // );
                        // console.log(
                        //   "  * Auth Code        :",
                        //   byteArrToHexStr(outabAuthCode.value as number[])
                        // );
                        // console.log("Verify Drone ID.");
                        // iRv = await Kse.DimDidVerify(
                        //   outabDid.value,
                        //   outsDidLen.value as number,
                        //   outabAuthCode.value,
                        //   KseDim.DID_ECDSA,
                        //   sKeyIndex
                        // );
                        // if (iRv !== KseDim.KSE_SUCCESS) {
                        //   Kse.DebugPrintErrStr("DimDidVerify()");
                        //   return;
                        // }
                        // console.log("Did test complete.");
                        // Power off KSE.
                        // sRv = await Kse.PowerOff();
                        ////////////////////////////////////////////////////////////////////////////
                        //// setup code end ////////////////////////////////////////////////////////
                        ////////////////////////////////////////////////////////////////////////////
                        return [2 /*return*/];
                    case 3:
                        e_4 = _a.sent();
                        console.log("Booting the client has failed.");
                        return [2 /*return*/];
                    case 4: return [2 /*return*/];
                }
            });
        }); };
        //// Request handling ////////////////////////////////////////////////////////
        this.handleAuthRequest = function (message) { return __awaiter(_this, void 0, void 0, function () {
            var request, clientId, iSocketDesc;
            return __generator(this, function (_a) {
                try {
                    request = JSON.parse(message);
                    if (request.method !== "MQTT")
                        return [2 /*return*/];
                    clientId = request.clientId;
                    iSocketDesc = request.sessionId;
                    if (this.channelInfo[iSocketDesc] === null ||
                        this.channelInfo[iSocketDesc] === undefined) {
                        //console.log(`Socket descriptor(${iSocketDesc}) is not registered.`);
                        return [2 /*return*/];
                    }
                    switch (request.type) {
                        case Constants_1.TLS_CONNECT: {
                            req_enc_count = 0;
                            req_sig_count = 0;
                            this.tlsClientConnectBuffer.requests.push(request);
                            break;
                        }
                        case Constants_1.TLS_HANDSHAKE: {
                            this.tlsHandshakeBuffer.requests.push(request);
                            break;
                        }
                        case Constants_1.TLS_DECRYPT: {
                            this.tlsEncryptBuffer.requests.push(request);
                            this.startTlsRead(clientId, iSocketDesc);
                            break;
                        }
                        default:
                            return [2 /*return*/];
                    }
                }
                catch (e) {
                    //      console.log("handleAuthRequest() error: ", e.toString());
                    console.log("handleAuthRequest() error: ");
                    return [2 /*return*/];
                }
                return [2 /*return*/];
            });
        }); };
        this.handleEncryptRequest = function (data) { return __awaiter(_this, void 0, void 0, function () {
            var bCh, abData, Kse, sRv, e_5;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        if (this.giSocketDesc === -1) {
                            //console.log("TLS session is not open yet.");
                            return [2 /*return*/];
                        }
                        console.log("Data to encrypt is received: ", data);
                        console.log("Req enc count: ", req_enc_count++);
                        bCh = this.channelInfo[this.giSocketDesc];
                        if (bCh === null || bCh === undefined) {
                            console.log("A channel is not found with the socket descriptor(" + this.giSocketDesc + ") [2].");
                            return [2 /*return*/];
                        }
                        abData = (0, Converter_1.hexStrToByteArr)(data);
                        Kse = this.gKse;
                        return [4 /*yield*/, Kse.KsetlsTlsWrite("none", bCh, abData)];
                    case 1:
                        sRv = _a.sent();
                        if (sRv === KseDim_1.default.KSE_SUCCESS) {
                            console.log("KsetlsTlsWrite() : Success...");
                        }
                        else {
                            Kse.DebugPrintErrStr("KsetlsTlsWrite()");
                            return [2 /*return*/];
                        }
                        return [3 /*break*/, 3];
                    case 2:
                        e_5 = _a.sent();
                        //      console.log("handleEncryptRequest() error: ", e.toString());
                        console.log("handleAuthRequest() error: ");
                        return [2 /*return*/];
                    case 3: return [2 /*return*/];
                }
            });
        }); };
        this.handleSignRequest = function (data) { return __awaiter(_this, void 0, void 0, function () {
            var Kse, iSocketDesc, abData, bKeyIndex, abSig, outabDid, outabAuthCode, outsDidLen, sDidIndex, sKeyIndex, reqData, reqMetaData, request, message, e_6;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        if (this.giSocketDesc === -1) {
                            //console.log("TLS session is not open yet.");
                            return [2 /*return*/];
                        }
                        console.log("Data to sign is received: ", data);
                        console.log("Req sig count: ", req_sig_count++);
                        Kse = this.gKse;
                        iSocketDesc = this.giSocketDesc;
                        abData = (0, Converter_1.hexStrToByteArr)(data);
                        bKeyIndex = 0;
                        return [4 /*yield*/, Kse.KcmvpEcdsaSign(0, abData, bKeyIndex)];
                    case 1:
                        abSig = _a.sent();
                        if (abSig === null) {
                            Kse.DebugPrintErrStr("KcmvpEcdsaSign()");
                            return [2 /*return*/];
                        }
                        outabDid = new OutObject_1.OutByteArray();
                        outabAuthCode = new OutObject_1.OutByteArray();
                        outsDidLen = new OutObject_1.OutShort();
                        sDidIndex = 0;
                        sKeyIndex = 0;
                        // const iRv = await Kse.DimDidRead(
                        //   outabDid,
                        //   outsDidLen,
                        //   outabAuthCode,
                        //   sDidIndex,
                        //   KseDim.DID_ECDSA,
                        //   sKeyIndex
                        // );
                        // if (iRv !== KseDim.KSE_SUCCESS) {
                        //   Kse.DebugPrintErrStr("DimDidRead()");
                        //   return;
                        // }
                        outabDid.value = [
                            0x46,
                            0x61,
                            0x6b,
                            0x65,
                            0x20,
                            0x44,
                            0x72,
                            0x6f,
                            0x6e,
                            0x65,
                            0x20,
                            0x49,
                            0x44,
                            0x20,
                            0x20,
                        ];
                        outabDid.value = outabDid.value.concat((0, Converter_1.strToUtf8Arr)(iSocketDesc + ""));
                        console.log("Drone ID :", outabDid.value.reduce(function (accum, bDid) {
                            accum += String.fromCharCode(bDid);
                            return accum;
                        }, ""));
                        outabAuthCode.value = [
                            0x46,
                            0x61,
                            0x6b,
                            0x65,
                            0x20,
                            0x41,
                            0x75,
                            0x74,
                            0x68,
                            0x20,
                            0x43,
                            0x6f,
                            0x64,
                            0x65,
                        ];
                        console.log("Auth Code :", (0, Converter_1.byteArrToHexStr)(outabAuthCode.value));
                        reqData = {
                            message: (0, Converter_1.byteArrToHexStr)(abData),
                            signature: (0, Converter_1.byteArrToHexStr)(abSig),
                        };
                        reqMetaData = {
                            message: (0, Converter_1.byteArrToHexStr)(outabDid.value),
                            signature: (0, Converter_1.byteArrToHexStr)(outabAuthCode.value),
                        };
                        request = {
                            id: 0,
                            clientId: "none",
                            method: "MQTT",
                            type: Constants_1.REQ_VERIFY,
                            sessionId: iSocketDesc,
                            data: JSON.stringify(reqData),
                            metadata: JSON.stringify(reqMetaData),
                        };
                        message = JSON.stringify(request);
                        this.mqttClient.publish(Topics_1.TOPIC_MUV_DATA_LIB_SEC_REQ_AUTH, message);
                        console.log("ECDSA message is sent: ", (0, Converter_1.byteArrToHexStr)(abData));
                        console.log("ECDSA signature is sent: ", (0, Converter_1.byteArrToHexStr)(abSig));
                        return [2 /*return*/];
                    case 2:
                        e_6 = _a.sent();
                        //      console.log("handleSignRequest() error: ", e.toString());
                        console.log("handleAuthRequest() error: ");
                        return [2 /*return*/];
                    case 3: return [2 /*return*/];
                }
            });
        }); };
        this.mqttClient = mqttClient;
    }
    return DimClientHandler;
}());
exports.default = DimClientHandler;
//# sourceMappingURL=index.js.map