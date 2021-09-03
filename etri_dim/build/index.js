"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var mqtt_1 = __importDefault(require("mqtt"));
var Topics_1 = require("./dim/Topics");
var dim_1 = __importDefault(require("./dim"));
var isSecure = false;
var host = "localhost";
var port = isSecure ? "8883" : "1883";
var protocol = isSecure ? "mqtts" : "mqtt";
var protocolId = "MQTT";
var protocolVersion = 4;
var connectOptions = {
    host: host,
    port: port,
    protocol: protocol,
    keepalive: 10,
    protocolId: protocolId,
    protocolVersion: protocolVersion,
    clean: true,
    reconnectPeriod: 2000,
    connectTimeout: 2000,
    // key: fs.readFileSync("./server-key.pem"),
    // cert: fs.readFileSync("./server-crt.pem"),
    rejectUnauthorized: false,
};
var mqttClient;
var dimClientHandler;
try {
    mqttClient = mqtt_1.default.connect(connectOptions);
    dimClientHandler = new dim_1.default(mqttClient);
    dimClientHandler.startClient();
    mqttClient.on("connect", function () {
        try {
            console.log("MQTT client is connected.");
            mqttClient.subscribe(Topics_1.TOPIC_MUV_CONTROL_LIB_SEC_REQ_START);
            console.log("subscribe nCube auth start topic at " +
                Topics_1.TOPIC_MUV_CONTROL_LIB_SEC_REQ_START);
            mqttClient.subscribe(Topics_1.TOPIC_MUV_CONTROL_LIB_SEC_RES_AUTH);
            console.log("subscribe nCube auth request topic at " +
                Topics_1.TOPIC_MUV_CONTROL_LIB_SEC_RES_AUTH);
            mqttClient.subscribe(Topics_1.TOPIC_MUV_CONTROL_LIB_SEC_REQ_ENC);
            console.log("subscribe nCube encryption request topic at " +
                Topics_1.TOPIC_MUV_CONTROL_LIB_SEC_REQ_ENC);
            mqttClient.subscribe(Topics_1.TOPIC_MUV_CONTROL_LIB_SEC_REQ_SIG);
            console.log("subscribe nCube signing request topic at " +
                Topics_1.TOPIC_MUV_CONTROL_LIB_SEC_REQ_SIG);
            // Self handshake start.
            // setTimeout(() => {
            //   dimClientHandler.startTlsHandshake();
            // }, 1000);
        }
        catch (e) {
            //      console.log("mqttClient.on('connect') error: ", e.toString());
        }
    });
    mqttClient.on("message", function (topic, message, packet) {
        try {
            switch (topic) {
                case Topics_1.TOPIC_MUV_CONTROL_LIB_SEC_REQ_START: {
                    dimClientHandler.startTlsHandshake();
                    break;
                }
                case Topics_1.TOPIC_MUV_CONTROL_LIB_SEC_RES_AUTH: {
                    dimClientHandler.handleAuthRequest(message.toString());
                    break;
                }
                case Topics_1.TOPIC_MUV_CONTROL_LIB_SEC_REQ_ENC: {
                    dimClientHandler.handleEncryptRequest(message.toString());
                    break;
                }
                case Topics_1.TOPIC_MUV_CONTROL_LIB_SEC_REQ_SIG: {
                    dimClientHandler.handleSignRequest(message.toString());
                    break;
                }
                default:
                    return;
            }
        }
        catch (e) {
            //      console.log("mqttClient.on('message') error: ", e.toString());
        }
    });
}
catch (e) {
    //  console.log("mqtt.connect error: ", e.toString());
}
//# sourceMappingURL=index.js.map