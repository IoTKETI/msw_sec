/* eslint-disable prefer-const */
import HID, { Device } from "node-hid";
import { OutByte, OutByteArray, OutInt, OutShort } from "./OutObject";

export interface TlsWriteHandler {
  write(
    dataType: number,
    clientId: string,
    bCh: number,
    abData: number[],
  ): Promise<number>;
}

export interface TlsReadHandler {
  read(
    dataType: number,
    clientId: string,
    bCh: number,
    timeout: number,
  ): Promise<number[] | null>;
}

interface Mutex {
  isLocked: boolean;
}

////////////////////////////////////////////////////////////////////////////////
//// Class : KseDim ////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
export default class KseDim {
  //////////////////////////////////////////////////////////////////////////////
  //// Type Definitions ////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////////////////////////
  //// Constants ///////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////////

  //// Public ------------------------------------------------------------------

  //// KseDim //////////////////////////////////////////////////////////////////

  static MAX_CHANNEL_COUNT = 6;
  static MAX_KCMVP_KEY_COUNT = 64;
  static MAX_CERT_KEY_COUNT = 1024;
  static MAX_IO_DATA_SIZE = 2944;
  static MAX_INFO_FILE_SIZE = 1048576;

  static MAX_CTRL_DATA_SIZE = 128;
  static MAX_TRANSCEIVE_SIZE =
    KseDim.MAX_IO_DATA_SIZE + KseDim.MAX_CTRL_DATA_SIZE; // 3,072.

  //// KSE /////////////////////////////////////////////////////////////////////

  static KSE_TRUE = 1;
  static KSE_FALSE = 0;
  static NOT_USED = 0;

  static LC_MANUFACTURED = 0xff;
  static LC_ISSUED = 0x00;
  static LC_TERMINATED = 0xee;

  static VC_DISABLED = 0xff;
  static VC_TYPE_0 = 0x00;
  static VC_TYPE_1 = 0x01;
  static VC_TYPE_2 = 0x02;
  static VC_TYPE_3 = 0x03;
  static VC_TYPE_4 = 0x04;
  static VC_INFINITE = 0x00;

  static CLEAR_ALL = 0x00;
  static CLEAR_ISSUE_DATA_ONLY = 0x01;

  //// KCMVP ///////////////////////////////////////////////////////////////////

  static KCMVP_DES_KEY = 0x20;
  static KCMVP_TDES_KEY = 0x30;
  static KCMVP_AES128_KEY = 0x40;
  static KCMVP_AES192_KEY = 0x41;
  static KCMVP_AES256_KEY = 0x42;
  static KCMVP_ARIA128_KEY = 0x50;
  static KCMVP_ARIA192_KEY = 0x51;
  static KCMVP_ARIA256_KEY = 0x52;
  static KCMVP_HMAC_KEY = 0x70;
  static KCMVP_ECDSA_KEYPAIR = 0x80;
  static KCMVP_ECDSA_PRI_KEY = 0x81;
  static KCMVP_ECDSA_PUB_KEY = 0x82;
  static KCMVP_ECDH_KEYPAIR = 0x90;
  static KCMVP_ECDH_PRI_KEY = 0x91;
  static KCMVP_ECDH_PUB_KEY = 0x92;

  static KCMVP_KEY_INDEX = 0x0000;
  static CERT_KEY_INDEX = 0x8000;
  static AMI_KEY_INDEX = 0x8000;

  static ENCRYPT = 0;
  static DECRYPT = 1;

  //// Cert ////////////////////////////////////////////////////////////////////

  //// KSETLS //////////////////////////////////////////////////////////////////

  static KSETLS_MODE_TLS = 0;
  static KSETLS_MODE_DTLS = 1;

  static KSETLS_CLIENT = 0;
  static KSETLS_SERVER = 1;

  static NO_USE = 0xffff;

  static NONE = 0x00;
  static OPP_CERT = 0x01; // Opponent Certificate.
  static OPP_PUB_KEY = 0x02; // Opponent Public Key.
  static EKM = 0x04; // Exported Keying Material.
  static SESSION = 0x08; // Session ID.

  static KSETLS_TIMEOUT = 30000; // 30000ms, 30 seconds.
  static KSETLS_DATA_HANDSHAKE = 0;
  static KSETLS_DATA_ENCRYPT = 1;
  static KSETLS_DATA_CLOSE = 2;
  static KSETLS_DATA_WARNING = 3;

  static KSETLS_FULL_HANDSHAKE = 0;
  static KSETLS_ABBR_HANDSHAKE = 1;

  static DTLS_TIMEOUT_MIN = 8000; //  8000 ms,  8 sec.
  static DTLS_TIMEOUT_MAX = 60000; // 60000 ms, 60 sec.
  // [RFC 6347 P.24] Implementations SHOULD use an initial timer value of
  // 1 second (the minimum defined in RFC 6298 [RFC6298]) and double the
  // value at each retransmission, up to no less than the RFC 6298 maximum
  // of 60 seconds.
  // : kseTLS recommends the minimum time out to 8 seconds for minimum
  //   retransmission.

  static MAX_UDP_DATAGRAM_LEN = 1500;

  //// DIM /////////////////////////////////////////////////////////////////////

  static MAX_DRONE_ID_COUNT = 8;

  static DID_ONLY = 0x00;
  static DID_ECDSA = 0x01;
  static DID_HMAC = 0x02;

  //// KSE API Error Codes /////////////////////////////////////////////////////

  static ICC_SUCCESS = 0x0000;
  static ICC_FAIL = -0x8000; // 0x8000

  static ICC_FAIL_WRONG_INPUT = -0x0100; // 0xFF00
  static ICC_FAIL_NOT_SUPPORTED = -0x0101; // 0xFEFF
  static ICC_FAIL_NOT_POWERED_ON = -0x0102; // 0xFEFE
  static ICC_FAIL_ALREADY_POWERED_ON = -0x0103; // 0xFEFD
  static ICC_FAIL_ATR = -0x0104; // 0xFEFC
  static ICC_FAIL_PPS = -0x0105; // 0xFEFB
  static ICC_FAIL_TX = -0x0106; // 0xFEFA
  static ICC_FAIL_RX = -0x0107; // 0xFEF9
  static ICC_FAIL_CHAINING = -0x0108; // 0xFEF8
  static ICC_FAIL_APDU_FORMAT = -0x0109; // 0xFEF7
  static ICC_FAIL_UNKNOWN_CMD = -0x010a; // 0xFEF6
  static ICC_FAIL_STATE = -0x010b; // 0xFEF5
  static ICC_FAIL_CODE_VERIFY = -0x010c; // 0xFEF4
  static ICC_FAIL_CRYPTO_VERIFY = -0x010d; // 0xFEF3
  static ICC_FAIL_CERT_VERIFY = -0x010e; // 0xFEF2
  static ICC_FAIL_FLASH = -0x010f; // 0xFEF1

  static KSE_SUCCESS = 0x0000;
  static KSE_FAIL = -0x8000; // 0x8000

  static KSE_FAIL_WRONG_INPUT = -0x0200; // 0xFE00
  static KSE_FAIL_NOT_SUPPORTED = -0x0201; // 0xFDFF
  static KSE_FAIL_NOT_POWERED_ON = -0x0202; // 0xFDFE
  static KSE_FAIL_ALREADY_POWERED_ON = -0x0203; // 0xFDFD
  static KSE_FAIL_ATR = -0x0204; // 0xFDFC
  static KSE_FAIL_PPS = -0x0205; // 0xFDFB
  static KSE_FAIL_TX = -0x0206; // 0xFDFA
  static KSE_FAIL_RX = -0x0207; // 0xFDF9
  static KSE_FAIL_CHAINING = -0x0208; // 0xFDF8
  static KSE_FAIL_APDU_FORMAT = -0x0209; // 0xFDF7
  static KSE_FAIL_UNKNOWN_CMD = -0x020a; // 0xFDF6
  static KSE_FAIL_STATE = -0x020b; // 0xFDF5
  static KSE_FAIL_CODE_VERIFY = -0x020c; // 0xFDF4
  static KSE_FAIL_CRYPTO_VERIFY = -0x020d; // 0xFDF3
  static KSE_FAIL_CERT_VERIFY = -0x020e; // 0xFDF2
  static KSE_FAIL_FLASH = -0x020f; // 0xFDF1
  static KSE_FAIL_SPI_SEND_DATA = -0x0213; // 0xFDED
  static KSE_FAIL_SPI_RECV_DATA = -0x0214; // 0xFDEC
  static KSE_FAIL_SPI_TIME_OUT = -0x0215; // 0xFDEB
  static KSE_FAIL_UNKNOWN_ERR = -0x0210; // 0xFDF0

  static KSE_FAIL_USB_INIT = -0x0300; // 0xFD00
  static KSE_FAIL_USB_NO_DEVICES = -0x0301; // 0xFCFF
  static KSE_FAIL_USB_DEVICE_OPEN = -0x0302; // 0xFCFE
  static KSE_FAIL_USB_DETACH_KERNEL_DRIVER = -0x0303; // 0xFCFD
  static KSE_FAIL_USB_CLAIM_INTERFACE = -0x0304; // 0xFCFC
  static KSE_FAIL_USB_SEND_REPORT = -0x0305; // 0xFCFB
  static KSE_FAIL_USB_RECV_REPORT = -0x0306; // 0xFCFA
  static KSE_FAIL_NOT_FOUND = -0x0307; // 0xFCF9
  static KSE_FAIL_UNEXPECTED_RESP = -0x0308; // 0xFCF8
  static KSE_FAIL_UNEXPECTED_RESP_LEN = -0x0309; // 0xFCF7
  static KSE_FAIL_RECV_BUF_OVERFLOW = -0x030a; // 0xFCF6
  static KSE_FAIL_NO_USB_PERMISSION = -0x030b; // 0xFCF5

  static KSETLS_FRAGMENT_RECORD = 0x0004;
  // Fragment record.
  static KSETLS_HELLO_VERIFY_REQUEST = 0x0003;
  // Hello verify requested.
  static KSETLS_HANDSHAKE_IN_PROGRESS = 0x0002;
  // Handshake is not completed yet.
  static KSETLS_HANDSHAKE_DONE = 0x0001;
  // Handshake done.

  static KSETLS_SUCCESS = 0x0000;
  // Success.
  static KSETLS_FAIL = -0x0001;
  // Fail.

  static KSETLS_ERR_NET_CONFIG = -0x0040;
  // Failed to get ip address! Please check your network configuration.
  static KSETLS_ERR_NET_SOCKET_FAILED = -0x0042;
  // Failed to open a socket.
  static KSETLS_ERR_NET_CONNECT_FAILED = -0x0044;
  // The connection to the given server:port failed.
  static KSETLS_ERR_NET_BIND_FAILED = -0x0046;
  // Binding of the socket failed.
  static KSETLS_ERR_NET_LISTEN_FAILED = -0x0048;
  // Could not listen on the socket.
  static KSETLS_ERR_NET_ACCEPT_FAILED = -0x004a;
  // Could not accept the incoming connection.
  static KSETLS_ERR_NET_RECV_FAILED = -0x004c;
  // Reading information from the socket failed.
  static KSETLS_ERR_NET_SEND_FAILED = -0x004e;
  // Sending information through the socket failed.
  static KSETLS_ERR_NET_CONN_RESET = -0x0050;
  // Connection was reset by peer.
  static KSETLS_ERR_NET_UNKNOWN_HOST = -0x0052;
  // Failed to get an IP address for the given hostname.
  static KSETLS_ERR_NET_BUFFER_TOO_SMALL = -0x0043;
  // Buffer is too small to hold the data.
  static KSETLS_ERR_NET_INVALID_CONTEXT = -0x0045;
  // The context is invalid, eg because it was free()ed.
  static KSETLS_ERR_NET_POLL_FAILED = -0x0047;
  // Polling the net context failed.
  static KSETLS_ERR_NET_BAD_INPUT_DATA = -0x0049;
  // Input invalid.

  static KSETLS_ERR_TLS_FEATURE_UNAVAILABLE = -0x7080;
  // The requested feature is not available.
  static KSETLS_ERR_TLS_BAD_INPUT_DATA = -0x7100;
  // Bad input parameters to function.
  static KSETLS_ERR_TLS_INVALID_MAC = -0x7180;
  // Verification of the message MAC failed.
  static KSETLS_ERR_TLS_INVALID_RECORD = -0x7200;
  // An invalid SSL record was received.
  static KSETLS_ERR_TLS_CONN_EOF = -0x7280;
  // The connection indicated an EOF.
  static KSETLS_ERR_TLS_UNKNOWN_CIPHER = -0x7300;
  // An unknown cipher was received.
  static KSETLS_ERR_TLS_NO_CIPHER_CHOSEN = -0x7380;
  // The server has no ciphersuites in common with the client.
  static KSETLS_ERR_TLS_NO_RNG = -0x7400;
  // No RNG was provided to the SSL module.
  static KSETLS_ERR_TLS_NO_CLIENT_CERTIFICATE = -0x7480;
  // No client certification received from the client,
  // but required by the authentication mode.
  static KSETLS_ERR_TLS_CERTIFICATE_TOO_LARGE = -0x7500;
  // Our own certificate(s) is/are too large to send in an SSL message.
  static KSETLS_ERR_TLS_CERTIFICATE_REQUIRED = -0x7580;
  // The own certificate is not set, but needed by the server.
  static KSETLS_ERR_TLS_PRIVATE_KEY_REQUIRED = -0x7600;
  // The own private key or pre-shared key is not set, but needed.
  static KSETLS_ERR_TLS_CA_CHAIN_REQUIRED = -0x7680;
  // No CA Chain is set, but required to operate.
  static KSETLS_ERR_TLS_UNEXPECTED_MESSAGE = -0x7700;
  // An unexpected message was received from our peer.
  static KSETLS_ERR_TLS_FATAL_ALERT_MESSAGE = -0x7780;
  // A fatal alert message was received from our peer.
  static KSETLS_ERR_TLS_PEER_VERIFY_FAILED = -0x7800;
  // Verification of our peer failed.
  static KSETLS_ERR_TLS_PEER_CLOSE_NOTIFY = -0x7880;
  // The peer notified us that the connection is going
  // to be closed.
  static KSETLS_ERR_TLS_BAD_HS_CLIENT_HELLO = -0x7900;
  // Processing of the ClientHello handshake message failed.
  static KSETLS_ERR_TLS_BAD_HS_SERVER_HELLO = -0x7980;
  // Processing of the ServerHello handshake message
  // failed.
  static KSETLS_ERR_TLS_BAD_HS_CERTIFICATE = -0x7a00;
  // Processing of the Certificate handshake message failed.
  static KSETLS_ERR_TLS_BAD_HS_CERTIFICATE_REQUEST = -0x7a80;
  // Processing of the CertificateRequest handshake message failed.
  static KSETLS_ERR_TLS_BAD_HS_SERVER_KEY_EXCHANGE = -0x7b00;
  // Processing of the ServerKeyExchange handshake message failed.
  static KSETLS_ERR_TLS_BAD_HS_SERVER_HELLO_DONE = -0x7b80;
  // Processing of the ServerHelloDone handshake
  // message failed.
  static KSETLS_ERR_TLS_BAD_HS_CLIENT_KEY_EXCHANGE = -0x7c00;
  // Processing of the ClientKeyExchange handshake message failed.
  static KSETLS_ERR_TLS_BAD_HS_CLIENT_KEY_EXCHANGE_RP = -0x7c80;
  // Processing of the ClientKeyExchange handshake message failed
  // in DHM / ECDH Read Public.
  static KSETLS_ERR_TLS_BAD_HS_CLIENT_KEY_EXCHANGE_CS = -0x7d00;
  // Processing of the ClientKeyExchange handshake
  // message failed in DHM / ECDH Calculate Secret.
  static KSETLS_ERR_TLS_BAD_HS_CERTIFICATE_VERIFY = -0x7d80;
  // Processing of the CertificateVerify handshake message failed.
  static KSETLS_ERR_TLS_BAD_HS_CHANGE_CIPHER_SPEC = -0x7e00;
  // Processing of the ChangeCipherSpec handshake message failed.
  static KSETLS_ERR_TLS_BAD_HS_FINISHED = -0x7e80;
  // Processing of the Finished handshake message failed.
  static KSETLS_ERR_TLS_ALLOC_FAILED = -0x7f00;
  // Memory allocation failed.
  static KSETLS_ERR_TLS_HW_ACCEL_FAILED = -0x7f80;
  // Hardware acceleration function returned with error.
  static KSETLS_ERR_TLS_HW_ACCEL_FALLTHROUGH = -0x6f80;
  // Hardware acceleration function skipped / left alone data.
  static KSETLS_ERR_TLS_COMPRESSION_FAILED = -0x6f00;
  // Processing of the compression / decompression failed.
  static KSETLS_ERR_TLS_BAD_HS_PROTOCOL_VERSION = -0x6e80;
  // Handshake protocol not within min/max boundaries.
  static KSETLS_ERR_TLS_BAD_HS_NEW_SESSION_TICKET = -0x6e00;
  // Processing of the NewSessionTicket handshake message failed.
  static KSETLS_ERR_TLS_SESSION_TICKET_EXPIRED = -0x6d80;
  // Session ticket has expired.
  static KSETLS_ERR_TLS_PK_TYPE_MISMATCH = -0x6d00;
  // Public key type mismatch (eg, asked for RSA key
  // exchange and presented EC key).
  static KSETLS_ERR_TLS_UNKNOWN_IDENTITY = -0x6c80;
  // Unknown identity received (eg, PSK identity).
  static KSETLS_ERR_TLS_INTERNAL_ERROR = -0x6c00;
  // Internal error (eg, unexpected failure in lower-level module).
  static KSETLS_ERR_TLS_COUNTER_WRAPPING = -0x6b80;
  // A counter would wrap (eg, too many messages exchanged).
  static KSETLS_ERR_TLS_WAITING_SERVER_HELLO_RENEGO = -0x6b00;
  // Unexpected message at ServerHello in renegotiation.
  static KSETLS_ERR_TLS_HELLO_VERIFY_REQUIRED = -0x6a80;
  // DTLS client must retry for hello verification.
  static KSETLS_ERR_TLS_BUFFER_TOO_SMALL = -0x6a00;
  // A buffer is too small to receive or write a message.
  static KSETLS_ERR_TLS_NO_USABLE_CIPHERSUITE = -0x6980;
  // None of the common ciphersuites is usable (eg, no suitable certificate,
  // see debug messages).
  static KSETLS_ERR_TLS_WANT_READ = -0x6900;
  // No data of requested type currently available on underlying transport.
  static KSETLS_ERR_TLS_WANT_WRITE = -0x6880;
  // Connection requires a write call.
  static KSETLS_ERR_TLS_TIMEOUT = -0x6800;
  // The operation timed out.
  static KSETLS_ERR_TLS_CLIENT_RECONNECT = -0x6780;
  // The client initiated a reconnect from the same port.
  static KSETLS_ERR_TLS_UNEXPECTED_RECORD = -0x6700;
  // Record header looks valid but is not expected.
  static KSETLS_ERR_TLS_NON_FATAL = -0x6680;
  // The alert message received indicates a non-fatal error.
  static KSETLS_ERR_TLS_INVALID_VERIFY_HASH = -0x6600;
  // Couldn't set the hash for verifying CertificateVerify.
  static KSETLS_ERR_TLS_CONTINUE_PROCESSING = -0x6580;
  // Internal-only message signaling that further message-processing
  // should be done.
  static KSETLS_ERR_TLS_ASYNC_IN_PROGRESS = -0x6500;
  // The asynchronous operation is not completed yet.
  static KSETLS_ERR_TLS_EARLY_MESSAGE = -0x6480;
  // Internal-only message signaling that a message
  // arrived early.
  static KSETLS_ERR_TLS_CRYPTO_IN_PROGRESS = -0x7000;
  // A cryptographic operation failure in progress.

  //// Debug ///////////////////////////////////////////////////////////////////

  static SENT = 0;
  static RECV = 1;

  //// Private -----------------------------------------------------------------

  //// USB Communication ///////////////////////////////////////////////////////

  private TIMEOUT_MS = 5000;
  private REPORT_SIZE = 64;
  private VENDOR_ID = 0x25f8; // VID : Keypair
  private PRODUCT_ID = 0x9002; // PID : ETRI DIM
  private REP_ONE_BLOCK = 0xa5;
  private REP_FIRST_BLOCK = 0xa1;
  private REP_MIDDLE_BLOCK = 0x11;
  private REP_LAST_BLOCK = 0x15;

  //// KseDim //////////////////////////////////////////////////////////////////

  private KSE_POWER_OFF = 0;
  private KSE_POWER_ON = 1;

  //// KCMVP ///////////////////////////////////////////////////////////////////

  private KCMVP_DES = 0x20;
  private KCMVP_TDES = 0x30;
  private KCMVP_AES = 0x40;
  private KCMVP_ARIA = 0x50;
  private KCMVP_FAST_ARIA = 0x58;
  private KCMVP_SHA = 0x60;
  private KCMVP_HMAC_GEN = 0x70;
  private KCMVP_HMAC_VERI = 0x78;
  private KCMVP_ECDSA_SIGN = 0x80;
  private KCMVP_ECDSA_VERI = 0x88;
  private KCMVP_ECDH = 0x90;

  //////////////////////////////////////////////////////////////////////////////
  //// Properties //////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////////

  //// Public ------------------------------------------------------------------

  public gsKseLastErrorCode = KseDim.KSETLS_SUCCESS;
  public gfEnableDebugPrint = false;

  //// Private -----------------------------------------------------------------

  //// Mutex ///////////////////////////////////////////////////////////////////
  private gTrsvMutex: Mutex = {
    isLocked: false,
  };

  private gTlsMutex: Mutex = {
    isLocked: false,
  };

  private gaTlsMutex: Mutex[] = new Array(KseDim.MAX_CHANNEL_COUNT).fill({
    isLocked: false,
  });

  private gOpMutex: Mutex = {
    isLocked: false,
  };

  private gKcmvpMutex: Mutex = {
    isLocked: false,
  };

  //// USB Communication ///////////////////////////////////////////////////////
  private ghDevice: HID.HID | null = null;
  private gsTransceiveLastErrorCode = KseDim.KSE_FAIL_NOT_FOUND;

  //// KseDim //////////////////////////////////////////////////////////////////
  private gsKsePower = this.KSE_POWER_OFF;

  //// KSE /////////////////////////////////////////////////////////////////////
  private gbVcType = KseDim.VC_DISABLED;

  //// KSETLS //////////////////////////////////////////////////////////////////

  private gabEndpoint: number[] = new Array(KseDim.MAX_CHANNEL_COUNT);
  private gaabNetData: number[][] = new Array(KseDim.MAX_CHANNEL_COUNT).fill(
    new Array(KseDim.MAX_TRANSCEIVE_SIZE),
  );
  private gausNetDataLength: number[] = new Array(
    KseDim.MAX_CHANNEL_COUNT,
  ).fill(0);
  private tlsReadHanldler: TlsReadHandler;
  private tlsWriteHanldler: TlsWriteHandler;

  //// AMI /////////////////////////////////////////////////////////////////////

  //////////////////////////////////////////////////////////////////////////////
  //// Instance Constructor ////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////////
  constructor(
    tlsReadHanldler: TlsReadHandler,
    tlsWriteHanldler: TlsWriteHandler,
  ) {
    this.tlsReadHanldler = tlsReadHanldler;
    this.tlsWriteHanldler = tlsWriteHanldler;
  }

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
  public ArrayCopy = (
    src: number[],
    srcOff: number,
    dst: number[],
    dstOff: number,
    len: number,
  ): void => {
    for (let i = 0; i < len; i++) {
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
  public ArrayFill = (
    arr: number[],
    arrOff: number,
    value: number,
    len: number,
  ): void => {
    for (let i = 0; i < len; i++) {
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
  public ByteArrComp = (a1: number[], a2: number[]): boolean => {
    if (!a1 && !a2) return true;

    if ((!a1 && a2) || (a1 && !a2)) return false;

    if (a1.length !== a2.length) return false;

    for (let i = 0; i < a1.length; i++) {
      if (a1[i] !== a2[i]) return false;
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
  private Transceive = async (
    abSendData: number[],
  ): Promise<number[] | null> => {
    try {
      await this.MutexLock(this.gTrsvMutex);
      if (!this.ghDevice) {
        this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_NOT_FOUND;
        await this.MutexRelease(this.gTrsvMutex);
        return null;
      }
      // Send Data.
      let sSendLen: number = abSendData.length;
      const abOutReport: number[] = new Array(this.REPORT_SIZE).fill(0);
      let sLen: number;
      let sOffset = 0;
      let abInReport = new Array(this.REPORT_SIZE);
      const abOutBuffer = new Array(this.REPORT_SIZE + 1).fill(0);
      while (sSendLen > 0) {
        if (abOutReport[0] === 0x00 && sSendLen <= 60)
          abOutReport[0] = this.REP_ONE_BLOCK;
        else if (abOutReport[0] === 0x00 && sSendLen > 60)
          abOutReport[0] = this.REP_FIRST_BLOCK;
        else if (abOutReport[0] !== 0x00 && sSendLen > 60)
          abOutReport[0] = this.REP_MIDDLE_BLOCK;
        else abOutReport[0] = this.REP_LAST_BLOCK;

        sLen = sSendLen > 60 ? 60 : sSendLen;
        abOutReport[1] = 0x05;
        abOutReport[2] = sOffset;
        abOutReport[3] = sLen;
        this.ArrayCopy(abSendData, sOffset * 60, abOutReport, 4, sLen);
        sOffset++;
        sSendLen -= sLen;

        // Transceive Report.
        try {
          this.ArrayFill(abOutBuffer, 0, 0, abOutBuffer.length);
          this.ArrayCopy(abOutReport, 0, abOutBuffer, 1, this.REPORT_SIZE);
          this.ghDevice.write(abOutBuffer);
        } catch (e) {
          this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_USB_SEND_REPORT;
          await this.MutexRelease(this.gTrsvMutex);
          return null;
        }

        try {
          abInReport = this.ghDevice.readSync();
        } catch (e) {
          this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_USB_RECV_REPORT;
          await this.MutexRelease(this.gTrsvMutex);
          return null;
        }

        if (
          ((abOutReport[0] === this.REP_ONE_BLOCK ||
            abOutReport[0] === this.REP_LAST_BLOCK) &&
            (abInReport[1] !== 0x06 || abInReport[2] !== 0x00)) ||
          ((abOutReport[0] === this.REP_FIRST_BLOCK ||
            abOutReport[0] === this.REP_MIDDLE_BLOCK) &&
            (abInReport[0] !== abOutReport[0] ||
              abInReport[1] !== 0xfe ||
              abInReport[2] !== abOutReport[2] ||
              abInReport[3] !== abOutReport[3]))
        ) {
          this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP;
          await this.MutexRelease(this.gTrsvMutex);
          return null;
        }
      }

      // Receive Data.
      sOffset = 0;
      let sRecvLen: number = abInReport[3];
      if (sRecvLen > KseDim.MAX_TRANSCEIVE_SIZE) {
        this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_RECV_BUF_OVERFLOW;
        await this.MutexRelease(this.gTrsvMutex);
        return null;
      }
      const abIoBuffer = new Array(KseDim.MAX_TRANSCEIVE_SIZE).fill(0);
      this.ArrayCopy(abInReport, 4, abIoBuffer, 0, sRecvLen);

      if (abInReport[0] === this.REP_FIRST_BLOCK) {
        do {
          this.ArrayCopy(abInReport, 0, abOutReport, 0, 4);
          abOutReport[1] = 0xfe;

          // Transceive Report.
          try {
            this.ArrayFill(abOutBuffer, 0, 0, abOutBuffer.length);
            this.ArrayCopy(abOutReport, 0, abOutBuffer, 1, this.REPORT_SIZE);
            this.ghDevice.write(abOutBuffer);
          } catch (e) {
            this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_USB_SEND_REPORT;
            await this.MutexRelease(this.gTrsvMutex);
            return null;
          }

          try {
            abInReport = this.ghDevice.readSync();
          } catch (e) {
            this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_USB_RECV_REPORT;
            await this.MutexRelease(this.gTrsvMutex);
            return null;
          }

          sOffset = abInReport[2];
          sLen = abInReport[3];
          sRecvLen += sLen;
          if (sRecvLen > KseDim.MAX_TRANSCEIVE_SIZE) {
            this.gsTransceiveLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP;
            await this.MutexRelease(this.gTrsvMutex);
            return null;
          }
          this.ArrayCopy(abInReport, 4, abIoBuffer, sOffset * 60, sLen);
        } while (abInReport[0] === this.REP_MIDDLE_BLOCK);
      }
      const abRecvData: number[] = new Array(sRecvLen).fill(0);
      this.ArrayCopy(abIoBuffer, 0, abRecvData, 0, sRecvLen);

      await this.MutexRelease(this.gTrsvMutex);
      return abRecvData;
    } catch (e) {
      await this.MutexRelease(this.gTrsvMutex);
      return null;
    }
  };

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
  private GetKseDimDeviceList = (deviceList: Device[]): Device[] => {
    const KseDimList: Device[] = deviceList.filter(
      (device) =>
        device.vendorId === this.VENDOR_ID &&
        device.productId === this.PRODUCT_ID,
    );

    return KseDimList;
  };

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
  public async PowerOn(
    outabVer: OutByteArray,
    outbLifeCycle: OutByte,
    outabChipSerial: OutByteArray,
    outabSystemTitle: OutByteArray,
    outbVcType: OutByte,
    outbMaxVcRetryCount: OutByte,
    outsMaxChannelCount: OutShort,
    outsMaxKcmvpKeyCount: OutShort,
    outsMaxCertKeyCount: OutShort,
    outsMaxIoDataSize: OutShort,
    outiInfoFileSize: OutInt,
  ): Promise<number> {
    try {
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
        return KseDim.KSE_FAIL;
      }

      // Find HID devices.
      const deviceList: Device[] = HID.devices();
      if (!deviceList || deviceList.length === 0) {
        this.gsKseLastErrorCode = KseDim.KSE_FAIL_USB_NO_DEVICES;
        return KseDim.KSE_FAIL;
      }

      // Find DIM devices.
      const kseDeviceList: Device[] = this.GetKseDimDeviceList(deviceList);
      if (!kseDeviceList || kseDeviceList.length === 0) {
        this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_FOUND;
        return KseDim.KSE_FAIL;
      }

      // Connect DIM.
      kseDeviceList.every((kseDevice) => {
        if (kseDevice.path) {
          try {
            this.ghDevice = new HID.HID(kseDevice.path);
            return false;
          } catch (e) {
            return true;
          }
        }
      });

      if (!this.ghDevice) {
        this.gsKseLastErrorCode = KseDim.KSE_FAIL_USB_DEVICE_OPEN;
        return KseDim.KSE_FAIL;
      }

      // KSE Power On.
      const abTxData: number[] = [0x0a, 0x00];
      const abRxData: number[] | null = await this.Transceive(abTxData);
      if (!abRxData) {
        if (this.ghDevice) this.ghDevice.close();
        this.ghDevice = null;
        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
        return KseDim.KSE_FAIL;
      }

      const sLen: number = abRxData.length;
      if (sLen < 2) {
        if (this.ghDevice) this.ghDevice.close();
        this.ghDevice = null;
        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
        return KseDim.KSE_FAIL;
      }

      const sRv: number = (abRxData[0] << 8) | abRxData[1];
      if (
        (sRv === KseDim.KSE_SUCCESS && sLen !== 43) ||
        (sRv !== KseDim.KSE_SUCCESS && sLen !== 2)
      ) {
        if (this.ghDevice) this.ghDevice.close();
        this.ghDevice = null;
        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
        return KseDim.KSE_FAIL;
      }

      if (sRv !== KseDim.KSE_SUCCESS) {
        if (this.ghDevice) this.ghDevice.close();
        this.ghDevice = null;
        this.gsKseLastErrorCode = sRv;
        return KseDim.KSE_FAIL;
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

      return sRv;
    } catch (e) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNKNOWN_ERR;
      return KseDim.KSE_FAIL;
    }
  }

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
  public PowerOff = async (): Promise<number> => {
    try {
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
        // Find HID devices.
        const deviceList: Device[] = HID.devices();
        if (!deviceList || deviceList.length === 0) {
          this.gsKseLastErrorCode = KseDim.KSE_FAIL_USB_NO_DEVICES;
          return KseDim.KSE_FAIL;
        }

        // Find DIM devices.
        const kseDeviceList: Device[] = this.GetKseDimDeviceList(deviceList);
        if (!kseDeviceList || kseDeviceList.length === 0) {
          this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_FOUND;
          return KseDim.KSE_FAIL;
        }

        // Connect DIM.
        kseDeviceList.every((kseDevice) => {
          if (kseDevice.path) {
            try {
              this.ghDevice = new HID.HID(kseDevice.path);
              return false;
            } catch (e) {
              return true;
            }
          }
        });
        if (!this.ghDevice) {
          this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_FOUND;
          this.gsKsePower = this.KSE_POWER_OFF;
          return KseDim.KSE_SUCCESS;
        }
      }

      // KSE Power Off.
      const abTxData: number[] = [0x0a, 0xff];
      const abRxData: number[] | null = await this.Transceive(abTxData);
      if (!abRxData) {
        if (this.ghDevice) this.ghDevice.close();
        this.ghDevice = null;
        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
        return KseDim.KSE_FAIL;
      }

      const sLen: number = abRxData.length;
      if (sLen !== 2) {
        if (this.ghDevice) this.ghDevice.close();
        this.ghDevice = null;
        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
        return KseDim.KSE_FAIL;
      }

      const sRv: number = (abRxData[0] << 8) | abRxData[1];
      if (sRv !== KseDim.KSE_SUCCESS) {
        if (this.ghDevice) this.ghDevice.close();
        this.ghDevice = null;
        this.gsKseLastErrorCode = sRv;
        return KseDim.KSE_FAIL;
      }

      if (this.ghDevice) this.ghDevice.close();
      this.ghDevice = null;
      this.gsKsePower = this.KSE_POWER_OFF;

      return sRv;
    } catch (e) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNKNOWN_ERR;
      return KseDim.KSE_FAIL;
    }
  };

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
  public DebugPrintNetTxRxData = (bMode: number, abData: number[]): void => {
    if (this.gfEnableDebugPrint !== true) return;

    if (bMode === KseDim.SENT) console.log("    + Sent Data:");
    else console.log("    + Received Data:");

    let i = 0;
    let message = "";
    for (i = 0; i < abData.length; i++) {
      message += ("0" + abData[i].toString(16)).substr(-2);
      if (i % 16 === 15 || i === abData.length - 1) {
        console.log(message);
        message = "";
      }
    }

    if (bMode === KseDim.SENT)
      console.log("    + Sent Data Length: ", abData.length);
    else console.log("    + Received Data Length: ", abData.length);

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
  public ErrStr = (): string => {
    let strKseErr: string;

    if (this.gsKseLastErrorCode === KseDim.KSE_SUCCESS) strKseErr = "Success";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL) strKseErr = "Fail";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_WRONG_INPUT)
      strKseErr = "ICC wrong input";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_NOT_SUPPORTED)
      strKseErr = "ICC not supported";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_NOT_POWERED_ON)
      strKseErr = "ICC not powered on";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_ALREADY_POWERED_ON)
      strKseErr = "ICC already powered on";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_ATR)
      strKseErr = "ICC ATR error";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_PPS)
      strKseErr = "ICC PPS error";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_TX)
      strKseErr = "ICC Tx error";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_RX)
      strKseErr = "ICC Rx error";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_CHAINING)
      strKseErr = "ICC chaining error";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_APDU_FORMAT)
      strKseErr = "ICC wrong APDU format";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_UNKNOWN_CMD)
      strKseErr = "ICC unknown command";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_STATE)
      strKseErr = "ICC state error";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_CODE_VERIFY)
      strKseErr = "ICC code verification error";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_CRYPTO_VERIFY)
      strKseErr = "ICC crypto verification error";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_CERT_VERIFY)
      strKseErr = "ICC certificate verification error";
    else if (this.gsKseLastErrorCode === KseDim.ICC_FAIL_FLASH)
      strKseErr = "ICC flash memory error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_WRONG_INPUT)
      strKseErr = "KSE wrong input";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_NOT_SUPPORTED)
      strKseErr = "KSE not supported";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_NOT_POWERED_ON)
      strKseErr = "KSE not powered on";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_ALREADY_POWERED_ON)
      strKseErr = "KSE already powered on";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_ATR)
      strKseErr = "KSE ATR error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_PPS)
      strKseErr = "KSE PPS error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_TX)
      strKseErr = "KSE Tx error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_RX)
      strKseErr = "KSE Rx error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_CHAINING)
      strKseErr = "KSE chaining error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_APDU_FORMAT)
      strKseErr = "KSE wrong APDU format";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_UNKNOWN_CMD)
      strKseErr = "KSE unknown command";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_STATE)
      strKseErr = "KSE state error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_CODE_VERIFY)
      strKseErr = "KSE code verification error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_CRYPTO_VERIFY)
      strKseErr = "KSE crypto verification error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_CERT_VERIFY)
      strKseErr = "KSE certificate verification error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_FLASH)
      strKseErr = "KSE flash memory error";
    else if ((this.gsKseLastErrorCode & 0xff00) === 0x6f00)
      strKseErr = `[${("000" + this.gsKseLastErrorCode.toString(16)).substr(
        -4,
      )}] CLIB error.`;
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_INIT)
      strKseErr = "USB initialization error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_NO_DEVICES)
      strKseErr = "No USB devices";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_DEVICE_OPEN)
      strKseErr = "USB device open error";
    else if (
      this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_DETACH_KERNEL_DRIVER
    )
      strKseErr = "USB detach kernel driver error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_CLAIM_INTERFACE)
      strKseErr = "USB claim interface driver error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_SEND_REPORT)
      strKseErr = "USB send report error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_USB_RECV_REPORT)
      strKseErr = "USB receive report error";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_NOT_FOUND)
      strKseErr = "KSE not found";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_UNEXPECTED_RESP)
      strKseErr = "KSE unexpected response";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN)
      strKseErr = "KSE unexpected response length";
    else if (this.gsKseLastErrorCode === KseDim.KSE_FAIL_RECV_BUF_OVERFLOW)
      strKseErr = "USB receive buffer overflow";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_FRAGMENT_RECORD)
      strKseErr = "Fragment record";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_HELLO_VERIFY_REQUEST)
      strKseErr = "Hello verify requested";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_HANDSHAKE_IN_PROGRESS)
      strKseErr = "Handshake is not completed yet";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_HANDSHAKE_DONE)
      strKseErr = "Handshake done";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_CONFIG)
      strKseErr =
        "Failed to get ip address! Please check your " +
        "network configuration";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_SOCKET_FAILED)
      strKseErr = "Failed to open a socket";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_CONNECT_FAILED)
      strKseErr = "The connection to the given server:port failed";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_BIND_FAILED)
      strKseErr = "Binding of the socket failed";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_LISTEN_FAILED)
      strKseErr = "Could not listen on the socket";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_ACCEPT_FAILED)
      strKseErr = "Could not accept the incoming connection";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_RECV_FAILED)
      strKseErr = "Reading information from the socket failed";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_SEND_FAILED)
      strKseErr = "Sending information through the socket failed";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_CONN_RESET)
      strKseErr = "Connection was reset by peer";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_UNKNOWN_HOST)
      strKseErr = "Failed to get an IP address for the given " + "hostname";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_BUFFER_TOO_SMALL)
      strKseErr = "Buffer is too small to hold the data";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_INVALID_CONTEXT)
      strKseErr = "The context is invalid, eg because it was " + "free()ed";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_POLL_FAILED)
      strKseErr = "Polling the net context failed";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_NET_BAD_INPUT_DATA)
      strKseErr = "Input invalid";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_FEATURE_UNAVAILABLE
    )
      strKseErr = "The requested feature is not available";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_INPUT_DATA)
      strKseErr = "Bad input parameters to function";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_INVALID_MAC)
      strKseErr = "Verification of the message MAC failed";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_INVALID_RECORD)
      strKseErr = "An invalid SSL record was received";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CONN_EOF)
      strKseErr = "The connection indicated an EOF";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_UNKNOWN_CIPHER)
      strKseErr = "An unknown cipher was received";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_NO_CIPHER_CHOSEN)
      strKseErr =
        "The server has no ciphersuites in common with " + "the client";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_NO_RNG)
      strKseErr = "No RNG was provided to the SSL module";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_NO_CLIENT_CERTIFICATE
    )
      strKseErr =
        "No client certification received from the " +
        "client, but required by the authentication mode";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CERTIFICATE_TOO_LARGE
    )
      strKseErr =
        "Our own certificate(s) is/are too large to send " +
        "in an SSL message";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CERTIFICATE_REQUIRED
    )
      strKseErr =
        "The own certificate is not set, but needed by " + "the server";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_PRIVATE_KEY_REQUIRED
    )
      strKseErr =
        "The own private key or pre-shared key is not " + "set, but needed";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CA_CHAIN_REQUIRED
    )
      strKseErr = "No CA Chain is set, but required to operate";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_UNEXPECTED_MESSAGE
    )
      strKseErr = "An unexpected message was received from our peer";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_FATAL_ALERT_MESSAGE
    )
      strKseErr = "A fatal alert message was received from our peer";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_PEER_VERIFY_FAILED
    )
      strKseErr = "Verification of our peer failed";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_PEER_CLOSE_NOTIFY
    )
      strKseErr =
        "The peer notified us that the connection is " + "going to be closed";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_HS_CLIENT_HELLO
    )
      strKseErr = "Processing of the ClientHello handshake message " + "failed";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_HS_SERVER_HELLO
    )
      strKseErr = "Processing of the ServerHello handshake message " + "failed";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_HS_CERTIFICATE
    )
      strKseErr = "Processing of the Certificate handshake message " + "failed";
    else if (
      this.gsKseLastErrorCode ===
      KseDim.KSETLS_ERR_TLS_BAD_HS_CERTIFICATE_REQUEST
    )
      strKseErr =
        "Processing of the CertificateRequest handshake " + "message failed";
    else if (
      this.gsKseLastErrorCode ===
      KseDim.KSETLS_ERR_TLS_BAD_HS_SERVER_KEY_EXCHANGE
    )
      strKseErr =
        "Processing of the ServerKeyExchange handshake " + "message failed";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_HS_SERVER_HELLO_DONE
    )
      strKseErr =
        "Processing of the ServerHelloDone handshake " + "message failed";
    else if (
      this.gsKseLastErrorCode ===
      KseDim.KSETLS_ERR_TLS_BAD_HS_CLIENT_KEY_EXCHANGE
    )
      strKseErr =
        "Processing of the ClientKeyExchange handshake " + "message failed";
    else if (
      this.gsKseLastErrorCode ===
      KseDim.KSETLS_ERR_TLS_BAD_HS_CLIENT_KEY_EXCHANGE_RP
    )
      strKseErr =
        "Processing of the ClientKeyExchange handshake " +
        "message failed in DHM / ECDH Read Public";
    else if (
      this.gsKseLastErrorCode ===
      KseDim.KSETLS_ERR_TLS_BAD_HS_CLIENT_KEY_EXCHANGE_CS
    )
      strKseErr =
        "Processing of the ClientKeyExchange handshake " +
        "message failed in DHM / ECDH Calculate Secret";
    else if (
      this.gsKseLastErrorCode ===
      KseDim.KSETLS_ERR_TLS_BAD_HS_CERTIFICATE_VERIFY
    )
      strKseErr =
        "Processing of the CertificateVerify handshake " + "message failed";
    else if (
      this.gsKseLastErrorCode ===
      KseDim.KSETLS_ERR_TLS_BAD_HS_CHANGE_CIPHER_SPEC
    )
      strKseErr =
        "Processing of the ChangeCipherSpec handshake " + "message failed";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_HS_FINISHED)
      strKseErr = "Processing of the Finished handshake message " + "failed";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_ALLOC_FAILED)
      strKseErr = "Memory allocation failed";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_HW_ACCEL_FAILED)
      strKseErr = "Hardware acceleration function returned with " + "error";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_HW_ACCEL_FALLTHROUGH
    )
      strKseErr =
        "Hardware acceleration function skipped / left " + "alone data";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_COMPRESSION_FAILED
    )
      strKseErr = "Processing of the compression / decompression " + "failed";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BAD_HS_PROTOCOL_VERSION
    )
      strKseErr = "Handshake protocol not within min/max boundaries";
    else if (
      this.gsKseLastErrorCode ===
      KseDim.KSETLS_ERR_TLS_BAD_HS_NEW_SESSION_TICKET
    )
      strKseErr =
        "Processing of the NewSessionTicket handshake " + "message failed";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_SESSION_TICKET_EXPIRED
    )
      strKseErr = "Session ticket has expired";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_PK_TYPE_MISMATCH)
      strKseErr =
        "Public key type mismatch (eg, asked for RSA key " +
        "exchange and presented EC key)";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_UNKNOWN_IDENTITY)
      strKseErr = "Unknown identity received (eg, PSK identity)";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_INTERNAL_ERROR)
      strKseErr =
        "Internal error (eg, unexpected failure in " + "lower-level module)";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_COUNTER_WRAPPING)
      strKseErr = "A counter would wrap (eg, too many messages " + "exchanged)";
    else if (
      this.gsKseLastErrorCode ===
      KseDim.KSETLS_ERR_TLS_WAITING_SERVER_HELLO_RENEGO
    )
      strKseErr = "Unexpected message at ServerHello in " + "renegotiation";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_HELLO_VERIFY_REQUIRED
    )
      strKseErr = "DTLS client must retry for hello verification";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_BUFFER_TOO_SMALL)
      strKseErr = "A buffer is too small to receive or write a " + "message";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_NO_USABLE_CIPHERSUITE
    )
      strKseErr =
        "None of the common ciphersuites is usable (eg, " +
        "no suitable certificate, see debug messages)";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_WANT_READ)
      strKseErr =
        "No data of requested type currently available " +
        "on underlying transport";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_WANT_WRITE)
      strKseErr = "Connection requires a write call";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_TIMEOUT)
      strKseErr = "The operation timed out";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CLIENT_RECONNECT)
      strKseErr = "The client initiated a reconnect from the same " + "port";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_UNEXPECTED_RECORD
    )
      strKseErr = "Record header looks valid but is not expected";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_NON_FATAL)
      strKseErr = "The alert message received indicates a " + "non-fatal error";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_INVALID_VERIFY_HASH
    )
      strKseErr = "Couldn't set the hash for verifying " + "CertificateVerify";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CONTINUE_PROCESSING
    )
      strKseErr =
        "Internal-only message signaling that further " +
        "message-processing should be done";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_ASYNC_IN_PROGRESS
    )
      strKseErr = "The asynchronous operation is not completed yet";
    else if (this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_EARLY_MESSAGE)
      strKseErr =
        "Internal-only message signaling that a message " + "arrived early";
    else if (
      this.gsKseLastErrorCode === KseDim.KSETLS_ERR_TLS_CRYPTO_IN_PROGRESS
    )
      strKseErr = "A cryptographic operation failure in progress.";
    else {
      strKseErr = `[${("000" + this.gsKseLastErrorCode.toString(16)).substr(
        -4,
      )}] KSE unknown error.`;
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
  public DebugPrintErrStr = (strErrFunc: string): void => {
    if (this.gfEnableDebugPrint !== true) return;

    console.log(strErrFunc + " : " + this.ErrStr());
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
  public KcmvpPutKey = async (
    bKeyType: number,
    usKeyIndex: number,
    abKey: number[],
  ): Promise<number> => {
    await this.MutexLock(this.gKcmvpMutex);
    this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }

    // Check input.
    if (
      (bKeyType !== KseDim.KCMVP_DES_KEY &&
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
      (bKeyType === KseDim.KCMVP_HMAC_KEY && abKey.length > 255)
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }
    const usKeySize: number = abKey.length;

    // Put the key.
    let abTxData: number[];
    if (bKeyType !== KseDim.KCMVP_HMAC_KEY) abTxData = new Array(usKeySize + 5);
    else abTxData = new Array(usKeySize + 7);
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
    const abRxData: number[] | null = await this.Transceive(abTxData);
    if (!abRxData) {
      this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }
    const usLen = abRxData.length;
    if (usLen !== 2) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }
    const sRv: number = (abRxData[0] << 8) | abRxData[1];
    if (sRv !== KseDim.KSE_SUCCESS) {
      this.gsKseLastErrorCode = sRv;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }

    await this.MutexRelease(this.gKcmvpMutex);
    return KseDim.KSE_SUCCESS;
  };

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
  public KcmvpEraseKey = async (
    bKeyType: number,
    usKeyIndex: number,
  ): Promise<number> => {
    await this.MutexLock(this.gKcmvpMutex);
    this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL_NOT_POWERED_ON;
    }

    // Check input.
    if (
      (bKeyType !== KseDim.KCMVP_DES_KEY &&
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
      usKeyIndex >= KseDim.MAX_KCMVP_KEY_COUNT
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }

    // Erase the key.
    const abTxData = new Array(5);
    abTxData[0] = 0x02;
    abTxData[1] = 0x03;
    abTxData[2] = bKeyType;
    abTxData[3] = (usKeyIndex >> 8) & 0xff;
    abTxData[4] = usKeyIndex & 0xff;
    const abRxData: number[] | null = await this.Transceive(abTxData);
    if (!abRxData) {
      this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }
    let usLen: number = abRxData.length;
    if (usLen !== 2) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }
    const sRv = (abRxData[0] << 8) | abRxData[1];
    if (sRv !== KseDim.KSE_SUCCESS) {
      this.gsKseLastErrorCode = sRv;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }

    await this.MutexRelease(this.gKcmvpMutex);
    return KseDim.KSE_SUCCESS;
  };

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
  private KcmvpHashDsa = async (
    bCh: number,
    abInput: number[] | null,
    abMessage: number[],
    usKeyIndex: number,
    bAlg: number,
  ): Promise<number[] | null> => {
    await this.MutexLock(this.gKcmvpMutex);

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
      await this.MutexRelease(this.gKcmvpMutex);
      return null;
    }

    // Check input.
    let bKeyIndexMask: number = (usKeyIndex & 0x8000) >> 8;
    usKeyIndex &= 0x7fff;
    if (abMessage === null) abMessage = new Array(0);
    if (
      bCh >= KseDim.MAX_CHANNEL_COUNT ||
      (bAlg === this.KCMVP_HMAC_VERI &&
        (abInput === null || abInput.length !== 32)) ||
      (bAlg === this.KCMVP_ECDSA_VERI &&
        (abInput === null || abInput.length !== 64)) ||
      ((bAlg === this.KCMVP_HMAC_GEN || bAlg === this.KCMVP_HMAC_VERI) &&
        (bKeyIndexMask === 0x80 || usKeyIndex >= KseDim.MAX_KCMVP_KEY_COUNT)) ||
      ((bAlg === this.KCMVP_ECDSA_SIGN || bAlg === this.KCMVP_ECDSA_VERI) &&
        ((bKeyIndexMask === 0x00 && usKeyIndex >= KseDim.MAX_KCMVP_KEY_COUNT) ||
          (bKeyIndexMask === 0x80 && usKeyIndex >= KseDim.MAX_CERT_KEY_COUNT)))
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
      await this.MutexRelease(this.gKcmvpMutex);
      return null;
    }
    let ulMessageSize: number = abMessage.length;

    // Hash, MAC, Signature, Verification - One step.
    let i: number;
    let sRv: number;
    let usSize: number, usLen: number;
    let abTxData: number[];
    let abRxData: number[] | null;
    if (ulMessageSize <= KseDim.MAX_IO_DATA_SIZE) {
      if (bAlg === this.KCMVP_SHA) usSize = 4;
      else if (bAlg === this.KCMVP_HMAC_VERI) usSize = 38;
      else if (bAlg === this.KCMVP_ECDSA_SIGN) usSize = 7;
      else if (bAlg === this.KCMVP_ECDSA_VERI) usSize = 71;
      else usSize = 6;
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
        this.ArrayCopy(abInput as number[], 0, abTxData, i, 32);
      else if (bAlg === this.KCMVP_ECDSA_VERI)
        this.ArrayCopy(abInput as number[], 0, abTxData, i, 64);
      abRxData = await this.Transceive(abTxData);
    }

    // Hash, MAC, Signature, Verification - Multi steps.
    else {
      // Hash, MAC, Signature, Verification - Begin.
      if (bAlg === this.KCMVP_HMAC_GEN || bAlg === this.KCMVP_HMAC_VERI)
        usSize = 7;
      else usSize = 5;
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
      abRxData = await this.Transceive(abTxData);
      if (abRxData === null) {
        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
        await this.MutexRelease(this.gKcmvpMutex);
        return null;
      }
      usLen = abRxData.length;
      if (usLen !== 2) {
        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
        await this.MutexRelease(this.gKcmvpMutex);
        return null;
      }
      sRv = (abRxData[0] << 8) | abRxData[1];
      if (sRv !== KseDim.KSE_SUCCESS) {
        this.gsKseLastErrorCode = sRv;
        await this.MutexRelease(this.gKcmvpMutex);
        return null;
      }
      let ulMessageOffset: number = KseDim.MAX_IO_DATA_SIZE;
      ulMessageSize -= KseDim.MAX_IO_DATA_SIZE;

      // Hash, MAC, Signature, Verification - Mid.
      while (ulMessageSize > KseDim.MAX_IO_DATA_SIZE) {
        abTxData = new Array(KseDim.MAX_IO_DATA_SIZE + 5);
        abTxData[0] = 0x02;
        abTxData[1] = (bAlg | 0x06) & 0xff;
        abTxData[2] = bCh;
        abTxData[3] = (KseDim.MAX_IO_DATA_SIZE >> 8) & 0xff;
        abTxData[4] = KseDim.MAX_IO_DATA_SIZE & 0xff;
        this.ArrayCopy(
          abMessage,
          ulMessageOffset,
          abTxData,
          5,
          KseDim.MAX_IO_DATA_SIZE,
        );
        abRxData = await this.Transceive(abTxData);
        if (abRxData === null) {
          this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
          await this.MutexRelease(this.gKcmvpMutex);
          return null;
        }
        usLen = abRxData.length;
        if (usLen !== 2) {
          this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
          await this.MutexRelease(this.gKcmvpMutex);
          return null;
        }
        sRv = (abRxData[0] << 8) | abRxData[1];
        if (sRv !== KseDim.KSE_SUCCESS) {
          this.gsKseLastErrorCode = sRv;
          await this.MutexRelease(this.gKcmvpMutex);
          return null;
        }
        ulMessageOffset += KseDim.MAX_IO_DATA_SIZE;
        ulMessageSize -= KseDim.MAX_IO_DATA_SIZE;
      }

      // Hash, MAC, Signature, Verification - End.
      if (bAlg === this.KCMVP_ECDSA_SIGN) usSize = 8;
      else if (bAlg === this.KCMVP_ECDSA_VERI) usSize = 72;
      else if (bAlg === this.KCMVP_HMAC_VERI) usSize = 37;
      else usSize = 5;
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
        this.ArrayCopy(abInput as number[], 0, abTxData, i, 32);
      else if (bAlg === this.KCMVP_ECDSA_VERI)
        this.ArrayCopy(abInput as number[], 0, abTxData, i, 64);
      abRxData = await this.Transceive(abTxData);
    }

    if (abRxData === null) {
      this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
      await this.MutexRelease(this.gKcmvpMutex);
      return null;
    }
    usLen = abRxData.length;
    if (usLen < 2) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      await this.MutexRelease(this.gKcmvpMutex);
      return null;
    }
    sRv = (abRxData[0] << 8) | abRxData[1];
    if (
      (sRv === KseDim.KSE_SUCCESS &&
        (((bAlg === this.KCMVP_SHA || bAlg === this.KCMVP_HMAC_GEN) &&
          usLen !== 34) ||
          (bAlg === this.KCMVP_ECDSA_SIGN && usLen !== 66))) ||
      ((sRv !== KseDim.KSE_SUCCESS ||
        bAlg === this.KCMVP_HMAC_VERI ||
        bAlg === this.KCMVP_ECDSA_VERI) &&
        usLen !== 2)
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      await this.MutexRelease(this.gKcmvpMutex);
      return null;
    }
    if (sRv !== KseDim.KSE_SUCCESS) {
      this.gsKseLastErrorCode = sRv;
      await this.MutexRelease(this.gKcmvpMutex);
      return null;
    }
    let abOutput: number[] | null = null;
    if (bAlg === this.KCMVP_SHA || bAlg === this.KCMVP_HMAC_GEN) {
      abOutput = new Array(32);
      this.ArrayCopy(abRxData, 2, abOutput, 0, 32);
    } else if (bAlg === this.KCMVP_ECDSA_SIGN) {
      abOutput = new Array(64);
      this.ArrayCopy(abRxData, 2, abOutput, 0, 64);
    }

    await this.MutexRelease(this.gKcmvpMutex);
    return abOutput;
  };

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
  public KcmvpEcdsaSign = async (
    bCh: number,
    abMessage: number[],
    usKeyIndex: number,
  ): Promise<number[] | null> => {
    return await this.KcmvpHashDsa(
      bCh,
      null,
      abMessage,
      usKeyIndex,
      this.KCMVP_ECDSA_SIGN,
    );
  };

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
  public KcmvpEcdsaVerify = async (
    bCh: number,
    abMessage: number[],
    abRs: number[],
    usKeyIndex: number,
  ): Promise<number> => {
    await this.MutexLock(this.gOpMutex);
    await this.KcmvpHashDsa(
      bCh,
      abRs,
      abMessage,
      usKeyIndex,
      this.KCMVP_ECDSA_VERI,
    );
    if (this.gsKseLastErrorCode !== KseDim.KSE_SUCCESS) {
      await this.MutexRelease(this.gOpMutex);
      return KseDim.KSE_FAIL;
    } else {
      await this.MutexRelease(this.gOpMutex);
      return KseDim.KSE_SUCCESS;
    }
  };

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
  private TlsRecv = async (
    iDataType: number,
    abData: number[],
    clientId: string,
    bCh: number,
    iTimeout: number,
  ): Promise<number> => {
    let sInLen = 0;
    try {
      const abRecv = await this.tlsReadHanldler.read(
        iDataType,
        clientId,
        bCh,
        iTimeout,
      );
      if (!abRecv) {
        sInLen = KseDim.KSETLS_ERR_NET_RECV_FAILED;
      } else {
        sInLen = abRecv.length;
        this.ArrayCopy(abRecv, 0, abData, 0, sInLen);
      }
    } catch (e) {
      sInLen = KseDim.KSETLS_ERR_NET_RECV_FAILED;
    }
    if (this.gfEnableDebugPrint === true && sInLen >= 0) {
      const abRecvData: number[] = new Array(sInLen);
      this.ArrayCopy(abData, 0, abRecvData, 0, sInLen);
      this.DebugPrintNetTxRxData(KseDim.RECV, abRecvData);
    }

    return sInLen;
  };

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
  private TlsSend = async (
    iDataType: number,
    clientId: string,
    bCh: number,
    abData: number[],
  ): Promise<number> => {
    let sOutLen = -1;
    try {
      sOutLen = await this.tlsWriteHanldler.write(
        iDataType,
        clientId,
        bCh,
        abData,
      );
      if (sOutLen < 0) sOutLen = KseDim.KSETLS_ERR_NET_SEND_FAILED;
    } catch (e) {
      sOutLen = KseDim.KSETLS_ERR_NET_SEND_FAILED;
    }
    if (this.gfEnableDebugPrint === true && sOutLen >= 0)
      this.DebugPrintNetTxRxData(KseDim.SENT, abData);

    return sOutLen;
  };

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
  public KsetlsOpen = async (
    bCh: number,
    bMode: number,
    bEndpoint: number,
    usKseDevCertIndex: number,
    usKseSubCaCertIndex: number,
    usKseRootCaCertIndex: number,
    usSessionInfoIndex: number,
    usOppDevCertIndex: number,
    usOppSubCaCertIndex: number,
    usEkmIndex: number,
  ): Promise<number> => {
    // await this.MutexLock(this.gaTlsMutex[bCh]);
    this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    // Check input.
    if (
      bCh >= KseDim.MAX_CHANNEL_COUNT ||
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
      (usEkmIndex !== KseDim.NO_USE && usEkmIndex >= KseDim.MAX_CERT_KEY_COUNT)
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    // Setup kseTLS channel.
    const abTxData: number[] = new Array(19);
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
    const abRxData: number[] | null = await this.Transceive(abTxData);
    if (!abRxData) {
      this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }
    const sLen: number = abRxData.length;
    if (sLen !== 2) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }
    const sRv: number = (abRxData[0] << 8) | abRxData[1];
    if (sRv !== KseDim.KSE_SUCCESS) {
      this.gsKseLastErrorCode = sRv;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    // Backup end point.
    this.gabEndpoint[bCh] = bEndpoint;
    this.gausNetDataLength[bCh] = 0;

    // await this.MutexRelease(this.gaTlsMutex[bCh]);
    return KseDim.KSE_SUCCESS;
  };

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
  public KsetlsReset = async (bCh: number): Promise<number> => {
    // await this.MutexLock(this.gaTlsMutex[bCh]);
    this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    // Check input.
    if (bCh >= KseDim.MAX_CHANNEL_COUNT) {
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL_WRONG_INPUT;
    }

    // Reset kseTLS channel.
    const abTxData: number[] = new Array(3);
    abTxData[0] = 0x06;
    abTxData[1] = 0x01;
    abTxData[2] = bCh;
    const abRxData: number[] | null = await this.Transceive(abTxData);
    if (!abRxData) {
      this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }
    const sLen: number = abRxData.length;
    if (sLen !== 2) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }
    const sRv: number = (abRxData[0] << 8) | abRxData[1];
    if (sRv !== KseDim.KSE_SUCCESS) {
      this.gsKseLastErrorCode = sRv;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    this.gausNetDataLength[bCh] = 0;

    // await this.MutexRelease(this.gaTlsMutex[bCh]);
    return KseDim.KSE_SUCCESS;
  };

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
  public KsetlsClose = async (bCh: number): Promise<number> => {
    // await this.MutexLock(this.gaTlsMutex[bCh]);
    this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    // Check input.
    if (bCh >= KseDim.MAX_CHANNEL_COUNT) {
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL_WRONG_INPUT;
    }

    // Close kseTLS channel.
    const abTxData: number[] = new Array(3);
    abTxData[0] = 0x06;
    abTxData[1] = 0x02;
    abTxData[2] = bCh;
    const abRxData: number[] | null = await this.Transceive(abTxData);
    if (!abRxData) {
      this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }
    const sLen: number = abRxData.length;
    if (sLen !== 2) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }
    const sRv: number = (abRxData[0] << 8) | abRxData[1];
    if (sRv !== KseDim.KSE_SUCCESS) {
      this.gsKseLastErrorCode = sRv;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    this.gausNetDataLength[bCh] = 0;

    // await this.MutexRelease(this.gaTlsMutex[bCh]);
    return KseDim.KSE_SUCCESS;
  };

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
  public KsetlsTlsClientHandshake = async (
    clientId: string,
    bCh: number,
    bType: number,
  ): Promise<number> => {
    await this.MutexLock(this.gaTlsMutex[bCh]);
    this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
      await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    // Check input.
    if (
      !clientId ||
      bCh >= KseDim.MAX_CHANNEL_COUNT ||
      (bType !== KseDim.KSETLS_FULL_HANDSHAKE &&
        bType !== KseDim.KSETLS_ABBR_HANDSHAKE)
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
      await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    let abTxData: number[];
    let abRxData: number[] | null;
    let sRv: number, sInLen: number, sOutLen: number;
    let usLen: number, usRecordLen: number, usUnusedInputLen: number;

    // TLS Client Handshake.
    let bNextInput: number = KseDim.KSE_FALSE;
    this.gausNetDataLength[bCh] = 0;
    do {
      // Receive Record.
      if (bNextInput === KseDim.KSE_TRUE) {
        if (this.gausNetDataLength[bCh] === 0) {
          sInLen = await this.TlsRecv(
            KseDim.KSETLS_DATA_HANDSHAKE,
            this.gaabNetData[bCh],
            clientId,
            bCh,
            KseDim.KSETLS_TIMEOUT,
          );
          if (sInLen < 0) {
            this.gsKseLastErrorCode = sInLen;
            await this.MutexRelease(this.gaTlsMutex[bCh]);
            return KseDim.KSE_FAIL;
          }
        } else sInLen = this.gausNetDataLength[bCh];
      } else sInLen = 0;

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
      abRxData = await this.Transceive(abTxData);
      if (!abRxData) {
        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
        await this.MutexRelease(this.gaTlsMutex[bCh]);
        return KseDim.KSE_FAIL;
      }
      usLen = abRxData.length;
      if (usLen < 2) {
        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
        await this.MutexRelease(this.gaTlsMutex[bCh]);
        return KseDim.KSE_FAIL;
      }
      sRv = (abRxData[0] << 8) | abRxData[1];
      if (sRv === KseDim.KSE_SUCCESS && usLen < 7) {
        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
        await this.MutexRelease(this.gaTlsMutex[bCh]);
        return KseDim.KSE_FAIL;
      }
      if (usLen > 2) {
        usUnusedInputLen = (abRxData[2] << 8) | abRxData[3];
        bNextInput = abRxData[4];
        usRecordLen = (abRxData[5] << 8) | abRxData[6];
      } else {
        usUnusedInputLen = 0;
        bNextInput = KseDim.KSE_FALSE;
        usRecordLen = 0;
      }

      // Send Record.
      if (usRecordLen > 0) {
        abTxData = new Array(usRecordLen);
        this.ArrayCopy(abRxData, 7, abTxData, 0, usRecordLen);
        sOutLen = await this.TlsSend(
          KseDim.KSETLS_DATA_HANDSHAKE,
          clientId,
          bCh,
          abTxData,
        );
        if (sOutLen < 0) {
          this.gsKseLastErrorCode = sOutLen;
          await this.MutexRelease(this.gaTlsMutex[bCh]);
          return KseDim.KSE_FAIL;
        }
      }

      // Next.
      if (usUnusedInputLen > 0) {
        abRxData = new Array(usUnusedInputLen);
        this.ArrayCopy(
          this.gaabNetData[bCh],
          sInLen - usUnusedInputLen,
          abRxData,
          0,
          usUnusedInputLen,
        );
        this.ArrayCopy(abRxData, 0, this.gaabNetData[bCh], 0, usUnusedInputLen);
        this.gausNetDataLength[bCh] = usUnusedInputLen;
      } else this.gausNetDataLength[bCh] = usUnusedInputLen;
    } while (sRv === KseDim.KSE_SUCCESS);

    if (sRv === KseDim.KSETLS_HANDSHAKE_DONE) sRv = KseDim.KSE_SUCCESS;

    if (sRv !== KseDim.KSE_SUCCESS) {
      this.gsKseLastErrorCode = sRv;
      await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    await this.MutexRelease(this.gaTlsMutex[bCh]);
    return KseDim.KSE_SUCCESS;
  };

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
  public KsetlsTlsServerHandshake = async (
    clientId: string,
    bCh: number,
  ): Promise<number> => {
    // await this.MutexLock(this.gaTlsMutex[bCh]);
    this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    // Check input.
    if (!clientId || bCh >= KseDim.MAX_CHANNEL_COUNT) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    let abTxData: number[];
    let abRxData: number[] | null;
    let sRv: number, sInLen: number, sOutLen: number;
    let usLen: number, usRecordLen: number, usUnusedInputLen: number;

    // TLS Server Handshake.
    let bNextInput: number = KseDim.KSE_TRUE;
    this.gausNetDataLength[bCh] = 0;
    do {
      // Receive Record.
      if (bNextInput === KseDim.KSE_TRUE) {
        if (this.gausNetDataLength[bCh] === 0) {
          sInLen = await this.TlsRecv(
            KseDim.KSETLS_DATA_HANDSHAKE,
            this.gaabNetData[bCh],
            clientId,
            bCh,
            KseDim.KSETLS_TIMEOUT,
          );
          if (sInLen < 0) {
            this.gsKseLastErrorCode = sInLen;
            // await this.MutexRelease(this.gaTlsMutex[bCh]);
            return KseDim.KSE_FAIL;
          }
        } else sInLen = this.gausNetDataLength[bCh];
      } else sInLen = 0;

      // Process Handshake.
      abTxData = new Array(sInLen + 5);
      abTxData[0] = 0x06;
      abTxData[1] = 0x11;
      abTxData[2] = bCh;
      abTxData[3] = (sInLen >> 8) & 0xff;
      abTxData[4] = sInLen & 0xff;
      if (sInLen > 0)
        this.ArrayCopy(this.gaabNetData[bCh], 0, abTxData, 5, sInLen);
      abRxData = await this.Transceive(abTxData);
      if (!abRxData) {
        this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
        // await this.MutexRelease(this.gaTlsMutex[bCh]);
        return KseDim.KSE_FAIL;
      }
      usLen = abRxData.length;
      if (usLen < 2) {
        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
        // await this.MutexRelease(this.gaTlsMutex[bCh]);
        return KseDim.KSE_FAIL;
      }

      sRv = (abRxData[0] << 8) | abRxData[1];
      if (sRv === KseDim.KSE_SUCCESS && usLen < 7) {
        this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
        // await this.MutexRelease(this.gaTlsMutex[bCh]);
        return KseDim.KSE_FAIL;
      }
      if (usLen > 2) {
        usUnusedInputLen = (abRxData[2] << 8) | abRxData[3];
        bNextInput = abRxData[4];
        usRecordLen = (abRxData[5] << 8) | abRxData[6];
      } else {
        usUnusedInputLen = 0;
        bNextInput = KseDim.KSE_FALSE;
        usRecordLen = 0;
      }

      // Send Record.
      if (usRecordLen > 0) {
        abTxData = new Array(usRecordLen);
        this.ArrayCopy(abRxData, 7, abTxData, 0, usRecordLen);
        sOutLen = await this.TlsSend(
          KseDim.KSETLS_DATA_HANDSHAKE,
          clientId,
          bCh,
          abTxData,
        );
        if (sOutLen < 0) {
          this.gsKseLastErrorCode = sOutLen;
          // await this.MutexRelease(this.gaTlsMutex[bCh]);
          return KseDim.KSE_FAIL;
        }
      }

      // Next.
      if (usUnusedInputLen > 0) {
        abRxData = new Array(usUnusedInputLen);
        this.ArrayCopy(
          this.gaabNetData[bCh],
          sInLen - usUnusedInputLen,
          abRxData,
          0,
          usUnusedInputLen,
        );
        this.ArrayCopy(abRxData, 0, this.gaabNetData[bCh], 0, usUnusedInputLen);
        this.gausNetDataLength[bCh] = usUnusedInputLen;
      } else this.gausNetDataLength[bCh] = 0;
    } while (sRv === KseDim.KSE_SUCCESS);

    if (sRv === KseDim.KSETLS_HANDSHAKE_DONE) sRv = KseDim.KSE_SUCCESS;

    if (sRv !== KseDim.KSE_SUCCESS) {
      this.gsKseLastErrorCode = sRv;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    // await this.MutexRelease(this.gaTlsMutex[bCh]);
    return KseDim.KSE_SUCCESS;
  };

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
  public KsetlsOpenAndServerHandshake = async (
    bCh: number,
    bMode: number,
    bEndpoint: number,
    usKseDevCertIndex: number,
    usKseSubCaCertIndex: number,
    usKseRootCaCertIndex: number,
    usSessionInfoIndex: number,
    usOppDevCertIndex: number,
    usOppSubCaCertIndex: number,
    usEkmIndex: number,
    clientId: string,
  ): Promise<number> => {
    let sRv;
    sRv = await this.KsetlsOpen(
      bCh,
      bMode,
      bEndpoint,
      usKseDevCertIndex,
      usKseSubCaCertIndex,
      usKseRootCaCertIndex,
      usSessionInfoIndex,
      usOppDevCertIndex,
      usOppSubCaCertIndex,
      usEkmIndex,
    );
    if (sRv !== KseDim.KSE_SUCCESS) {
      console.log("  KsetlsOpen() error.");
      return KseDim.KSE_FAIL;
    }

    console.log("KsetlsOpen() : Success...");
    console.log("  * Performing the TLS handshake...");
    sRv = await this.KsetlsTlsServerHandshake(clientId, bCh);
    if (sRv !== KseDim.KSE_SUCCESS) {
      console.log("  KsetlsTlsServerHandshake() error.");
      return KseDim.KSE_FAIL;
    }

    console.log("KsetlsTlsServerHandshake() : Success...");
    return KseDim.KSE_SUCCESS;
  };

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
  public KsetlsTlsRead = async (
    clientId: string,
    bCh: number,
  ): Promise<number[] | null> => {
    await this.MutexLock(this.gaTlsMutex[bCh]);
    this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
      await this.MutexRelease(this.gaTlsMutex[bCh]);
      return null;
    }

    // Check input.
    if (!clientId || bCh >= KseDim.MAX_CHANNEL_COUNT) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
      await this.MutexRelease(this.gaTlsMutex[bCh]);
      return null;
    }

    let sRv: number, sInLen: number, sOutLen: number;
    let abTxData: number[];
    let abRxData: number[] | null;
    let abInAppData: number[];
    let usLen: number;
    let usRecordLen: number, usUnusedInputLen: number, usMessageLen: number;

    // Read Record.
    if (this.gausNetDataLength[bCh] === 0) {
      // Receive Record.
      sInLen = await this.TlsRecv(
        KseDim.KSETLS_DATA_ENCRYPT,
        this.gaabNetData[bCh],
        clientId,
        bCh,
        KseDim.KSETLS_TIMEOUT,
      );
      if (sInLen < 0) {
        this.gsKseLastErrorCode = sInLen;
        return null;
      }
    } else sInLen = this.gausNetDataLength[bCh];

    // Parse Record.
    abTxData = new Array(sInLen + 5);
    abTxData[0] = 0x06;
    abTxData[1] = 0x20;
    abTxData[2] = bCh;
    abTxData[3] = (sInLen >> 8) & 0xff;
    abTxData[4] = sInLen & 0xff;
    if (sInLen > 0)
      this.ArrayCopy(this.gaabNetData[bCh], 0, abTxData, 5, sInLen);
    abRxData = await this.Transceive(abTxData);
    if (!abRxData) {
      this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
      await this.MutexRelease(this.gaTlsMutex[bCh]);
      return null;
    }
    usLen = abRxData.length;
    if (usLen < 2) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      await this.MutexRelease(this.gaTlsMutex[bCh]);
      return null;
    }
    sRv = (abRxData[0] << 8) | abRxData[1];
    if (
      (sRv === KseDim.KSE_SUCCESS && usLen < 6) ||
      (sRv !== KseDim.KSE_SUCCESS && usLen !== 2 && usLen !== 4)
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      await this.MutexRelease(this.gaTlsMutex[bCh]);
      return null;
    }
    if (sRv !== KseDim.KSE_SUCCESS) {
      if (usLen === 4) {
        // Set Alert.
        abTxData = new Array(5);
        abTxData[4] = abRxData[3];
        abTxData[3] = abRxData[2];
        abTxData[0] = 0x06;
        abTxData[1] = 0x22;
        abTxData[2] = bCh;
        abRxData = await this.Transceive(abTxData);
        if (!abRxData) {
          this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
          await this.MutexRelease(this.gaTlsMutex[bCh]);
          return null;
        }
        usLen = abRxData.length;
        if (usLen < 2) {
          this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
          await this.MutexRelease(this.gaTlsMutex[bCh]);
          return null;
        }
        sRv = (abRxData[0] << 8) | abRxData[1];
        if (
          (sRv === KseDim.KSE_SUCCESS && usLen < 4) ||
          (sRv !== KseDim.KSE_SUCCESS && usLen !== 2)
        ) {
          this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
          await this.MutexRelease(this.gaTlsMutex[bCh]);
          return null;
        }
        if (sRv !== KseDim.KSE_SUCCESS) {
          this.gsKseLastErrorCode = sRv;
          await this.MutexRelease(this.gaTlsMutex[bCh]);
          return null;
        }
        usRecordLen = (abRxData[2] << 8) | abRxData[3];

        // Send Record.
        if (usRecordLen > 0) {
          abTxData = new Array(usRecordLen);
          this.ArrayCopy(abRxData, 4, abTxData, 0, usRecordLen);
          sOutLen = await this.TlsSend(
            KseDim.KSETLS_DATA_WARNING,
            clientId,
            bCh,
            abTxData,
          );
          if (sOutLen < 0) {
            this.gsKseLastErrorCode = sOutLen;
            await this.MutexRelease(this.gaTlsMutex[bCh]);
            return null;
          }
        }
      }
      this.gausNetDataLength[bCh] = 0;

      this.gsKseLastErrorCode = sRv;
      await this.MutexRelease(this.gaTlsMutex[bCh]);
      return null;
    }
    usUnusedInputLen = (abRxData[2] << 8) | abRxData[3];
    usMessageLen = (abRxData[4] << 8) | abRxData[5];
    abInAppData = new Array(usMessageLen);
    this.ArrayCopy(abRxData, 6, abInAppData, 0, usMessageLen);

    if (usUnusedInputLen > 0) {
      abRxData = new Array(usUnusedInputLen);
      this.ArrayCopy(
        this.gaabNetData[bCh],
        sInLen - usUnusedInputLen,
        abRxData,
        0,
        usUnusedInputLen,
      );
      this.ArrayCopy(abRxData, 0, this.gaabNetData[bCh], 0, usUnusedInputLen);
      this.gausNetDataLength[bCh] = usUnusedInputLen;
    } else {
      this.gausNetDataLength[bCh] = 0;
    }

    await this.MutexRelease(this.gaTlsMutex[bCh]);
    return abInAppData;
  };

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
  public KsetlsTlsWrite = async (
    clientId: string,
    bCh: number,
    abOutAppData: number[],
  ): Promise<number> => {
    // await this.MutexLock(this.gaTlsMutex[bCh]);
    this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    // Check input.
    if (
      !clientId ||
      bCh >= KseDim.MAX_CHANNEL_COUNT ||
      !abOutAppData ||
      abOutAppData.length === 0 ||
      abOutAppData.length > KseDim.MAX_IO_DATA_SIZE
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    let sOutAppDataLen: number = abOutAppData.length;

    let sRv: number,
      sOutLen = 0;
    let abTxData: number[];
    let abRxData: number[] | null;
    let usLen: number, usRecordLen: number;

    // Set Record.
    abTxData = new Array(sOutAppDataLen + 5);
    abTxData[0] = 0x06;
    abTxData[1] = 0x21;
    abTxData[2] = bCh;
    abTxData[3] = (sOutAppDataLen >> 8) & 0xff;
    abTxData[4] = sOutAppDataLen & 0xff;
    this.ArrayCopy(abOutAppData, 0, abTxData, 5, sOutAppDataLen);
    abRxData = await this.Transceive(abTxData);
    if (!abRxData) {
      this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }
    usLen = abRxData.length;
    if (usLen < 2) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }
    sRv = (abRxData[0] << 8) | abRxData[1];
    if (
      (sRv === KseDim.KSE_SUCCESS && usLen < 4) ||
      (sRv !== KseDim.KSE_SUCCESS && usLen !== 2)
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }
    if (sRv !== KseDim.KSE_SUCCESS) {
      this.gsKseLastErrorCode = sRv;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    usRecordLen = (abRxData[2] << 8) | abRxData[3];

    // Send Record.
    if (usRecordLen > 0) {
      abTxData = new Array(usRecordLen);
      this.ArrayCopy(abRxData, 4, abTxData, 0, usRecordLen);
      sOutLen = await this.TlsSend(
        KseDim.KSETLS_DATA_ENCRYPT,
        clientId,
        bCh,
        abTxData,
      );
      if (sOutLen < 0) {
        this.gsKseLastErrorCode = sOutLen;
        // await this.MutexRelease(this.gaTlsMutex[bCh]);
        return KseDim.KSE_FAIL;
      }
    }
    this.gausNetDataLength[bCh] = 0;

    // await this.MutexRelease(this.gaTlsMutex[bCh]);
    return KseDim.KSE_SUCCESS;
  };

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
  public KsetlsTlsCloseNotify = async (
    clientId: string,
    bCh: number,
  ): Promise<number> => {
    // await this.MutexLock(this.gaTlsMutex[bCh]);
    this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    // Check input.
    if (!clientId || bCh >= KseDim.MAX_CHANNEL_COUNT) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }

    let sRv: number;
    let sOutLen = 0;
    let abTxData: number[];
    let abRxData: number[] | null;
    let usLen: number, usRecordLen: number;

    // Close notify.
    abTxData = new Array(6);
    abTxData[0] = 0x06;
    abTxData[1] = 0x23;
    abTxData[2] = bCh;
    abRxData = await this.Transceive(abTxData);
    if (abRxData === null) {
      this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }
    usLen = abRxData.length;
    if (usLen < 2) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }
    sRv = (abRxData[0] << 8) | abRxData[1];
    if (
      (sRv === KseDim.KSE_SUCCESS && usLen < 4) ||
      (sRv !== KseDim.KSE_SUCCESS && usLen !== 2)
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }
    if (sRv !== KseDim.KSE_SUCCESS) {
      this.gsKseLastErrorCode = sRv;
      // await this.MutexRelease(this.gaTlsMutex[bCh]);
      return KseDim.KSE_FAIL;
    }
    usRecordLen = (abRxData[2] << 8) | abRxData[3];

    // Send Record.
    if (usRecordLen > 0) {
      abTxData = new Array(usRecordLen);
      this.ArrayCopy(abRxData, 4, abTxData, 0, usRecordLen);
      sOutLen = await this.TlsSend(
        KseDim.KSETLS_DATA_CLOSE,
        clientId,
        bCh,
        abTxData,
      );
      if (sOutLen < 0) {
        this.gsKseLastErrorCode = sOutLen;
        // await this.MutexRelease(this.gaTlsMutex[bCh]);
        return KseDim.KSE_FAIL;
      }
    }
    this.gausNetDataLength[bCh] = 0;

    // await this.MutexRelease(this.gaTlsMutex[bCh]);
    return sOutLen;
  };

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
  public DimDidWrite = async (
    abDid: number[],
    sDidLen: number,
    sDidIndex: number,
  ): Promise<number> => {
    await this.MutexLock(this.gKcmvpMutex);
    this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }

    // Check input.
    if (
      sDidLen > 32 ||
      (sDidLen === 0 && abDid !== null) ||
      sDidIndex >= KseDim.MAX_DRONE_ID_COUNT
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }

    let sRv: number;
    let abTxData: number[];
    let abRxData: number[] | null;
    let sLen: number;

    // Write Drone ID.
    abTxData = new Array(5 + sDidLen);
    abTxData[0] = 0x0c;
    abTxData[1] = 0x00;
    abTxData[2] = (sDidIndex >> 8) & 0xff;
    abTxData[3] = sDidIndex & 0xff;
    abTxData[4] = sDidLen & 0xff;
    this.ArrayCopy(abDid, 0, abTxData, 5, sDidLen);

    abRxData = await this.Transceive(abTxData);
    if (abRxData === null) {
      this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }
    sLen = abRxData.length;
    if (sLen !== 2) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }
    sRv = (abRxData[0] << 8) | abRxData[1];
    if (sRv !== KseDim.KSE_SUCCESS) {
      this.gsKseLastErrorCode = sRv;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }

    await this.MutexRelease(this.gKcmvpMutex);
    return KseDim.KSE_SUCCESS;
  };

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
  public DimDidRead = async (
    outabDid: OutByteArray,
    outsDidLen: OutShort,
    outabAuthCode: OutByteArray,
    sDidIndex: number,
    bDidType: number,
    sKeyIndex: number,
  ): Promise<number> => {
    await this.MutexLock(this.gKcmvpMutex);
    this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }

    // Check input.
    const sKeyType: number = sKeyIndex >> 15;
    const sKeyIndexMask: number = sKeyIndex & 0x7fff;
    if (
      outabDid === null ||
      sDidIndex >= KseDim.MAX_DRONE_ID_COUNT ||
      bDidType > KseDim.DID_HMAC ||
      (bDidType === KseDim.DID_ONLY && sKeyIndex !== 0) ||
      (bDidType === KseDim.DID_ECDSA &&
        ((sKeyType === 0 && sKeyIndexMask >= KseDim.MAX_KCMVP_KEY_COUNT) ||
          (sKeyType === 1 && sKeyIndexMask >= KseDim.MAX_CERT_KEY_COUNT))) ||
      (bDidType === KseDim.DID_HMAC && sKeyIndex >= KseDim.MAX_KCMVP_KEY_COUNT)
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }

    // Read Drone ID.
    const abTxData: number[] = new Array(7);
    abTxData[0] = 0x0c;
    abTxData[1] = 0x01;
    abTxData[2] = (sDidIndex >> 8) & 0xff;
    abTxData[3] = sDidIndex & 0xff;
    abTxData[4] = bDidType;
    abTxData[5] = (sKeyIndex >> 8) & 0xff;
    abTxData[6] = sKeyIndex & 0xff;
    const abRxData: number[] | null = await this.Transceive(abTxData);
    if (!abRxData) {
      this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }
    const sLen: number = abRxData.length;
    if (sLen < 2) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }
    const sRv: number = (abRxData[0] << 8) | abRxData[1];
    const sDidLen: number = abRxData[2];
    if (
      (sRv === KseDim.KSE_SUCCESS &&
        ((bDidType === KseDim.DID_ONLY && sLen !== sDidLen + 3) ||
          (bDidType === KseDim.DID_ECDSA && sLen !== sDidLen + 67) ||
          (bDidType === KseDim.DID_HMAC && sLen !== sDidLen + 35))) ||
      (sRv !== KseDim.KSE_SUCCESS && sLen !== 2)
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }
    if (sRv !== KseDim.KSE_SUCCESS) {
      this.gsKseLastErrorCode = sRv;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }
    outabDid.value = abRxData.slice(3, 3 + sDidLen);

    if (bDidType === KseDim.DID_ECDSA)
      outabAuthCode.value = abRxData.slice(3 + sDidLen, 3 + sDidLen + 64);
    else if (bDidType === KseDim.DID_HMAC)
      outabAuthCode.value = abRxData.slice(3 + sDidLen, 3 + sDidLen + 32);
    outsDidLen.value = sDidLen;

    await this.MutexRelease(this.gKcmvpMutex);
    return KseDim.KSE_SUCCESS;
  };

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
  public DimDidVerify = async (
    abDid: number[] | null,
    sDidLen: number,
    abAuthCode: number[] | null,
    bDidType: number,
    sKeyIndex: number,
  ): Promise<number> => {
    await this.MutexLock(this.gKcmvpMutex);
    this.gsKseLastErrorCode = KseDim.KSE_SUCCESS;

    // Check KSE power state.
    if (this.gsKsePower !== this.KSE_POWER_ON) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_NOT_POWERED_ON;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }

    // Check input.
    const sKeyType: number = sKeyIndex >> 15;
    const sKeyIndexMask: number = sKeyIndex & 0x7fff;
    if (
      sDidLen === 0 ||
      sDidLen > 32 ||
      bDidType < KseDim.DID_ECDSA ||
      bDidType > KseDim.DID_HMAC ||
      (bDidType === KseDim.DID_ECDSA &&
        ((sKeyType === 0 && sKeyIndexMask >= KseDim.MAX_KCMVP_KEY_COUNT) ||
          (sKeyType === 1 && sKeyIndexMask >= KseDim.MAX_CERT_KEY_COUNT))) ||
      (bDidType === KseDim.DID_HMAC &&
        sKeyIndex >= KseDim.MAX_KCMVP_KEY_COUNT) ||
      abDid === null ||
      abAuthCode === null
    ) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_WRONG_INPUT;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }

    let sRv: number;
    let abTxData: number[];
    let abRxData: number[] | null;
    let sLen: number;

    // Verify Drone ID.
    abTxData = new Array(
      6 + sDidLen + (bDidType === KseDim.DID_ECDSA ? 64 : 32),
    );
    abTxData[0] = 0x0c;
    abTxData[1] = 0x02;
    abTxData[2] = bDidType;
    abTxData[3] = (sKeyIndex >> 8) & 0xff;
    abTxData[4] = sKeyIndex & 0xff;
    abTxData[5] = sDidLen;
    this.ArrayCopy(abDid, 0, abTxData, 6, sDidLen);
    if (bDidType === KseDim.DID_ECDSA) {
      this.ArrayCopy(abAuthCode, 0, abTxData, 6 + sDidLen, 64);
    } else {
      this.ArrayCopy(abAuthCode, 0, abTxData, 6 + sDidLen, 32);
    }

    abRxData = await this.Transceive(abTxData);
    if (abRxData === null) {
      this.gsKseLastErrorCode = this.gsTransceiveLastErrorCode;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }
    sLen = abRxData.length;
    if (sLen !== 2) {
      this.gsKseLastErrorCode = KseDim.KSE_FAIL_UNEXPECTED_RESP_LEN;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }
    sRv = (abRxData[0] << 8) | abRxData[1];
    if (sRv !== KseDim.KSE_SUCCESS) {
      this.gsKseLastErrorCode = sRv;
      await this.MutexRelease(this.gKcmvpMutex);
      return KseDim.KSE_FAIL;
    }

    await this.MutexRelease(this.gKcmvpMutex);
    return KseDim.KSE_SUCCESS;
  };

  //// Mutex ///////////////////////////////////////////////////////////////////

  private MutexLock = async (mutex: Mutex): Promise<number> => {
    if (mutex.isLocked) {
      const wait = (resolve: (value: number | PromiseLike<number>) => void) => {
        if (mutex.isLocked) {
          setTimeout(() => {
            wait(resolve);
          }, 50);
          return;
        }
        mutex.isLocked = true;
        resolve(KseDim.KSE_SUCCESS);
        return;
      };

      return new Promise((resolve): void => {
        try {
          wait(resolve);
          return;
        } catch (e) {
          mutex.isLocked = true;
          resolve(KseDim.KSE_FAIL);
          return;
        }
      });
    } else {
      mutex.isLocked = true;
      return KseDim.KSE_SUCCESS;
    }
  };

  private MutexRelease = async (mutex: Mutex): Promise<void> => {
    mutex.isLocked = false;
    return;
  };
}
