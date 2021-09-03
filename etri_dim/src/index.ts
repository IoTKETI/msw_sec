import mqtt, { MqttClient, Packet } from "mqtt";
import {
  TOPIC_MUV_CONTROL_LIB_SEC_REQ_ENC,
  TOPIC_MUV_CONTROL_LIB_SEC_REQ_SIG,
  TOPIC_MUV_CONTROL_LIB_SEC_REQ_START,
  TOPIC_MUV_CONTROL_LIB_SEC_RES_AUTH,
} from "./dim/Topics";
import DimClientHandler from "./dim";

const isSecure = false;
const host = "localhost";
const port = isSecure ? "8883" : "1883";
const protocol = isSecure ? "mqtts" : "mqtt";
const protocolId = "MQTT";
const protocolVersion = 4;

const connectOptions = {
  host,
  port,
  protocol,
  keepalive: 10,
  protocolId,
  protocolVersion,
  clean: true,
  reconnectPeriod: 2000,
  connectTimeout: 2000,
  // key: fs.readFileSync("./server-key.pem"),
  // cert: fs.readFileSync("./server-crt.pem"),
  rejectUnauthorized: false,
};

let mqttClient: MqttClient;
let dimClientHandler: DimClientHandler;

try {
  mqttClient = mqtt.connect(connectOptions);
  dimClientHandler = new DimClientHandler(mqttClient);
  dimClientHandler.startClient();
  mqttClient.on("connect", () => {
    try {
      console.log(`MQTT client is connected.`);

      mqttClient.subscribe(TOPIC_MUV_CONTROL_LIB_SEC_REQ_START);
      console.log(
        "subscribe nCube auth start topic at " +
          TOPIC_MUV_CONTROL_LIB_SEC_REQ_START,
      );

      mqttClient.subscribe(TOPIC_MUV_CONTROL_LIB_SEC_RES_AUTH);
      console.log(
        "subscribe nCube auth request topic at " +
          TOPIC_MUV_CONTROL_LIB_SEC_RES_AUTH,
      );

      mqttClient.subscribe(TOPIC_MUV_CONTROL_LIB_SEC_REQ_ENC);
      console.log(
        "subscribe nCube encryption request topic at " +
          TOPIC_MUV_CONTROL_LIB_SEC_REQ_ENC,
      );

      mqttClient.subscribe(TOPIC_MUV_CONTROL_LIB_SEC_REQ_SIG);
      console.log(
        "subscribe nCube signing request topic at " +
          TOPIC_MUV_CONTROL_LIB_SEC_REQ_SIG,
      );

      // Self handshake start.
      // setTimeout(() => {
      //   dimClientHandler.startTlsHandshake();
      // }, 1000);
    } catch (e) {
//      console.log("mqttClient.on('connect') error: ", e.toString());
    }
  });

  mqttClient.on("message", (topic: string, message: Buffer, packet: Packet) => {
    try {
      switch (topic) {
        case TOPIC_MUV_CONTROL_LIB_SEC_REQ_START: {
          dimClientHandler.startTlsHandshake();
          break;
        }
        case TOPIC_MUV_CONTROL_LIB_SEC_RES_AUTH: {
          dimClientHandler.handleAuthRequest(message.toString());
          break;
        }
        case TOPIC_MUV_CONTROL_LIB_SEC_REQ_ENC: {
          dimClientHandler.handleEncryptRequest(message.toString());
          break;
        }
        case TOPIC_MUV_CONTROL_LIB_SEC_REQ_SIG: {
          dimClientHandler.handleSignRequest(message.toString());
          break;
        }
        default:
          return;
      }
    } catch (e) {
//      console.log("mqttClient.on('message') error: ", e.toString());
    }
  });
} catch (e) {
//  console.log("mqtt.connect error: ", e.toString());
}
