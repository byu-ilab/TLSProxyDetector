/*
 * Flash TLS Proxy Detector
 * Copyright (c) 2014, Mark O'Neill, All rights reserved.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
*/
package  
{
	/**
	 * @author Mark O'Neill
	 */
	
	import adobe.utils.ProductManager;
	import flash.events.Event;
	import flash.events.EventDispatcher;
	import flash.events.IOErrorEvent;
	import flash.events.SecurityErrorEvent;
	import flash.net.Socket;
	import flash.events.ProgressEvent;
	import flash.utils.ByteArray;
	import flash.system.Security;
	import flash.utils.Endian;
	import mx.utils.Base64Encoder;
	import flash.external.ExternalInterface;
	
	public class CertificateCrawler extends EventDispatcher
	{
		
		// Crawler ID
		private var _crawlerID:uint;
		
		private var _debug:Boolean;
		
		// Current connection state
		private var _socket:Socket;
		private var _response:ByteArray;
		private var _currentHost:Object;
		private var _bytesToRead:uint;
		private var _serverHelloStarted:Boolean;
		private var _serverHelloEnded:Boolean;
		private var _serverCertificateStarted:Boolean;
		private var _serverCerificateEnded:Boolean;
		private var _tlsFrameStarted:Boolean;
		private var _stopRead:Boolean;
		private var _tlsFrameBytesToRead:uint;
		private var _serverHelloData:ByteArray;
		private var _serverCertificateData:ByteArray;
		private var _certChainString:String;
		private var _serverHelloString:String;
		
		// TLS Constants
		private var TLS_FRAME_HANDSHAKE_IDENTIFIER:uint = 0x0016;
		private var TLS_FRAME_HEADER_LENGTH:uint = 5;
		private var SERVER_HELLO_HEADER_LENGTH:uint = 6;
		
		// Handshake Constants
		private var HANDSHAKE_TYPE_CLIENT_HELLO:uint = 0x0001;
		private var HANDSHAKE_TYPE_SERVER_HELLO:uint = 0x0002;
		private var HANDSHAKE_TYPE_CERTIFICATE:uint = 0x000b;
		private var MAJOR_SSL_VERSION_THREE:uint = 0x0003;
		private var MINOR_SSL_VERSION_ONE:uint = 0x0001;
		
		// Cipher Suites
		private const TLS_EMPTY_RENEGOTIATION_INFO_SCSV:uint = 0x00ff;
		private const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:uint = 0xc00a;
		private const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:uint = 0xc014;
		private const TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:uint = 0x0088;
		private const TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:uint = 0x0087;
		private const TLS_DHE_RSA_WITH_AES_256_CBC_SHA:uint = 0x0039;
		private const TLS_DHE_DSS_WITH_AES_256_CBC_SHA:uint = 0x0038;
		private const TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:uint = 0xc00f;
		private const TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:uint = 0xc005;
		private const TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:uint = 0x0084;
		private const TLS_RSA_WITH_AES_256_CBC_SHA:uint = 0x0035;
		private const TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:uint = 0xc007;
		private const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:uint = 0xc009;
		private const TLS_ECDHE_RSA_WITH_RC4_128_SHA:uint = 0xc011;
		private const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:uint = 0xc013;
		private const TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:uint = 0x0045;
		private const TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:uint = 0x0044;
		private const TLS_DHE_RSA_WITH_AES_128_CBC_SHA:uint = 0x0033;
		private const TLS_DHE_DSS_WITH_AES_128_CBC_SHA:uint = 0x0032;
		private const TLS_ECDH_RSA_WITH_RC4_128_SHA:uint = 0xc00c;
		private const TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:uint = 0xc00e;
		private const TLS_ECDH_ECDSA_WITH_RC4_128_SHA:uint = 0xc002;
		private const TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:uint = 0xc004;
		private const TLS_RSA_WITH_SEED_CBC_SHA:uint = 0x0096;
		private const TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:uint = 0x0041;
		private const TLS_RSA_WITH_RC4_128_SHA:uint = 0x0005;
		private const TLS_RSA_WITH_RC4_128_MD5:uint = 0x0004;
		private const TLS_RSA_WITH_AES_128_CBC_SHA:uint = 0x002f;
		private const TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:uint = 0xc008;
		private const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:uint = 0xc012;
		private const TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:uint = 0x0016;
		private const TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:uint = 0x0013;
		private const TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:uint = 0xc00d;
		private const TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:uint = 0xc003;
		private const SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA:uint = 0xfeff;
		private const TLS_RSA_WITH_3DES_EDE_CBC_SHA:uint = 0x000a;
		
		public function CertificateCrawler(host:Object, crawlerID:uint, debug:Boolean) {
			
			debugPrint("Beginning test for " + host.name + ":" + host.port);
			// Attempt to load socket policy file from specified host and policy port
			//Security.loadPolicyFile("xmlsocket://" + host.name + ":" + host.pport);  // disabled for now
			_crawlerID = crawlerID;
			_debug = debug;
			
			// Assign global state
			_currentHost = host;
			_response = new ByteArray();
			_serverHelloStarted = false;
			_serverHelloEnded = false;
			_serverCertificateStarted = false;
			_serverCerificateEnded = false;
			_tlsFrameStarted = false;
			_stopRead = false;
			
			_serverHelloData = new ByteArray();
			_serverCertificateData = new ByteArray();
			_bytesToRead = 0;
			_certChainString = new String("");
			_serverHelloString = new String("");
			
			_socket = new Socket();
			_socket.addEventListener(Event.CONNECT, onSocketConnected);
			_socket.addEventListener(IOErrorEvent.IO_ERROR, onSocketError);
			_socket.addEventListener(SecurityErrorEvent.SECURITY_ERROR, onSocketSecurity);
			_socket.addEventListener(ProgressEvent.SOCKET_DATA, onSocketData);
		}
		
		public function start():void {
			_socket.connect(_currentHost.name, _currentHost.port);
		}
		
		private function debugPrint(message:String):void {
			if (!_debug) return;
			
			var wrappedMessage:String = "Crawler " + _crawlerID + ": " + message;
			if (ExternalInterface.available) {
				ExternalInterface.call("console.log", wrappedMessage);
			}
			trace(wrappedMessage);
			return;
		}

		private function bytesToHexString(ba:ByteArray):String {
			var hex:String = "";
			ba.position = 0;
			for (var i:uint = 0; i < ba.length; i++) {
				var byte:uint = ba.readUnsignedByte();
				var hexstr:String = byte.toString(16).substr( -2);
				if (hexstr.length < 2) hexstr = "0" + hexstr;
				hex += hexstr;
			}
			return hex;
		}

		private function createClientHello():ByteArray {
			var helloData:ByteArray = new ByteArray();
			helloData.endian = Endian.BIG_ENDIAN;
			
			// Create 4-byte gmt unix time
			var unix_gmt_time:uint = new Date().valueOf()/1000;
			helloData.writeUnsignedInt(unix_gmt_time); // date portion (4-byte)

			// Create "random" 28 bytes
			for (var i:uint = 0; i < 7; i++) {
				//var randomNum:uint = uint(Math.random() * (Math.pow(2,31) - 1));
				var randomNum:uint = uint(Math.pow(2,31) - 1); // We would use line above but Google Adwords does not allow Math.random() in ads
				helloData.writeUnsignedInt(randomNum);
			}
			
			// Set session ID length to 0 (means this is a new session)
			helloData.writeByte(0x00);

			// Set cipher suite support
			var cipherSuites:ByteArray = getSupportedCipherSuites();
			helloData.writeShort(cipherSuites.length);
			helloData.writeBytes(cipherSuites);
			
			// Set compression mode support
			helloData.writeByte(0x01); // 1 method
			helloData.writeByte(0x00); // null compression mode
			
			// Set extensions support
			var extensions:ByteArray = new ByteArray();
			extensions.endian = Endian.BIG_ENDIAN;
			
			// Server name extension (this is really hackish, but whatever)
			extensions.writeShort(0x0000); // server_name extension
			var hostname:ByteArray = new ByteArray();
			hostname.writeMultiByte(_currentHost.name, "us-ascii");
			extensions.writeShort(hostname.length + 5);
			extensions.writeShort(hostname.length + 3);
			extensions.writeByte(0x00);
			extensions.writeShort(hostname.length);
			extensions.writeBytes(hostname);
			
			// Other extensions (all these are hard-coded. will change if needed)
			extensions.writeShort(0x000a); // elliptic_curves extension type
			extensions.writeShort(0x0008); // length 8
			extensions.writeShort(0x0006); // elliptic curves length 6
			extensions.writeShort(0x0017); // Elliptic curve: secp256r1
			extensions.writeShort(0x0018); // Elliptic curve: secp384r1
			extensions.writeShort(0x0019); // Elliptic curve: secp521r1
			extensions.writeShort(0x000b); // ec_point_formats extension type
			extensions.writeShort(0x0002); // data length 2
			extensions.writeByte(0x01); // ec_point_format length 1
			extensions.writeByte(0x00);  // uncompressed format
			extensions.writeShort(0x0023); // sessionticket TLS extension type
			extensions.writeShort(0x0000); // zero data length
			extensions.writeShort(0x3374); // unknown extension type (firefox sent this and I just copied)
			extensions.writeShort(0x0000); // zero data length
			
			// Add extension data to frame
			helloData.writeShort(extensions.length);
			helloData.writeBytes(extensions);
			
			// Wrap data in TLS ClientHello header
			helloData = createClientHelloHeader(helloData);
			// Wrap data in TLS handshake header
			helloData = createTLSHandshakeHeader(helloData);
			
			return helloData;
		}
		
		private function createClientHelloHeader(ba:ByteArray):ByteArray {
			var helloFrame:ByteArray = new ByteArray();
			helloFrame.endian = Endian.BIG_ENDIAN;
			helloFrame.writeByte(HANDSHAKE_TYPE_CLIENT_HELLO);
			
			// Input hello data length (24-bit value)
			helloFrame.writeByte(0x00); // This can be zero as long as ba.length can fit into 16 bits
			helloFrame.writeShort(ba.length + 2); // add two for version length
			
			helloFrame.writeBytes(getTLSVersion());
			helloFrame.writeBytes(ba);
			return helloFrame;
		}
		
		private function createTLSHandshakeHeader(ba:ByteArray):ByteArray {
			var tlsFrame:ByteArray = new ByteArray();
			tlsFrame.endian = Endian.BIG_ENDIAN;
			tlsFrame.writeByte(0x16); // 0x16 is handshake
			tlsFrame.writeBytes(getTLSVersion());
			tlsFrame.writeShort(ba.length); // 16-bit size of data in frame
			tlsFrame.writeBytes(ba);
			return tlsFrame;
		}
		
		private function getTLSVersion():ByteArray {
			var ba:ByteArray = new ByteArray();
			ba.endian = Endian.BIG_ENDIAN;
			ba.writeByte(MAJOR_SSL_VERSION_THREE); // major SSL version (3)
			ba.writeByte(MINOR_SSL_VERSION_ONE); // minor SSL version (1)
			return ba;
		}
		
		private function getSupportedCipherSuites():ByteArray {
			var ba:ByteArray = new ByteArray();
			ba.endian = Endian.BIG_ENDIAN;
			
			
			// List of supported cipher suites
			// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
			ba.writeShort(TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
			ba.writeShort(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
			ba.writeShort(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
			ba.writeShort(TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA);
			ba.writeShort(TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA);
			ba.writeShort(TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
			ba.writeShort(TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
			ba.writeShort(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA);
			ba.writeShort(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);
			ba.writeShort(TLS_RSA_WITH_CAMELLIA_256_CBC_SHA);
			ba.writeShort(TLS_RSA_WITH_AES_256_CBC_SHA);
			ba.writeShort(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA);
			ba.writeShort(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
			ba.writeShort(TLS_ECDHE_RSA_WITH_RC4_128_SHA);
			ba.writeShort(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
			ba.writeShort(TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA);
			ba.writeShort(TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA);
			ba.writeShort(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
			ba.writeShort(TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
			ba.writeShort(TLS_ECDH_RSA_WITH_RC4_128_SHA);
			ba.writeShort(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
			ba.writeShort(TLS_ECDH_ECDSA_WITH_RC4_128_SHA);
			ba.writeShort(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
			ba.writeShort(TLS_RSA_WITH_SEED_CBC_SHA);
			ba.writeShort(TLS_RSA_WITH_CAMELLIA_128_CBC_SHA);
			ba.writeShort(TLS_RSA_WITH_RC4_128_SHA);
			ba.writeShort(TLS_RSA_WITH_RC4_128_MD5);
			ba.writeShort(TLS_RSA_WITH_AES_128_CBC_SHA);
			ba.writeShort(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
			ba.writeShort(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
			ba.writeShort(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
			ba.writeShort(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
			ba.writeShort(TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA);
			ba.writeShort(TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA);
			ba.writeShort(SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA);
			ba.writeShort(TLS_RSA_WITH_3DES_EDE_CBC_SHA);
			
			return ba;
		}
		
		protected function onSocketConnected(e:Event):void {
			debugPrint("Socket to " + _currentHost.name + ":" + _currentHost.port + " connected");
			var clientHello:ByteArray = createClientHello();
			_socket.writeBytes(clientHello);
			_socket.flush();
			debugPrint("Sent Client Hello: 0x" + bytesToHexString(clientHello));
			return;
		}
		
		protected function onSocketData(e:ProgressEvent):void {
			// Unwrap TLS frames and parse their internal data
			var response:ByteArray = new ByteArray();
			
			// Loop until we either have enough data to start parsing a TLS frame or have the full server certificate
			while (!_serverCerificateEnded && (_tlsFrameStarted || _socket.bytesAvailable >= TLS_FRAME_HEADER_LENGTH)) {
				response.position = 0; // seek to beginning of response

				if (!_tlsFrameStarted) { // If we haven't yet read enough to enter a TLS frame
					_socket.readBytes(response, 0, TLS_FRAME_HEADER_LENGTH); // Read TLS header data
					var protocolToken:uint = response.readUnsignedByte(); // should be 0x16 (handshake)
					var sslMajorVersion:uint = response.readUnsignedByte();
					var sslMinorVersion:uint = response.readUnsignedByte();
					var frameLength:uint = response.readUnsignedShort(); // 2-byte length of TLS frame
					
					_tlsFrameBytesToRead = frameLength; // set the number of bytes to read
					if (protocolToken == TLS_FRAME_HANDSHAKE_IDENTIFIER) {
						debugPrint("TLS frame handshake protocol token found! (token 0x" + protocolToken.toString(16)+")");
						debugPrint("TLS frame SSL Major Version: " + sslMajorVersion);
						debugPrint("TLS frame SSL Minor Version: " + sslMinorVersion);
						debugPrint("TLS frame length: " + frameLength);
						_tlsFrameStarted = true;
					}
					else {
						var error:String = "Error: expected TLS Protocol Token 0x16 (handshake), got " + protocolToken.toString(16);
						debugPrint(error);
						_stopRead = true;
						var results:Object = { host:_currentHost, message:error };
						dispatchEvent(new CrawlerEvent(CrawlerEvent.CRAWL_ERROR, results));
						break;
					}
				}
				
				// only attempt to parse frame data if we have already parsed a header for one
				if (_tlsFrameStarted) {
					// only attempt to parse frame data when we have received all bytes in frame
					if (_socket.bytesAvailable >= _tlsFrameBytesToRead) {
						parseTLSData(_tlsFrameBytesToRead);
					}
					else {
						break;
					}
				}
			}
		}
		
		private function parseTLSData(maxBytesToRead:uint):void {
			var response:ByteArray = new ByteArray();
			if (!_serverHelloStarted) {
				if (maxBytesToRead >= SERVER_HELLO_HEADER_LENGTH) {
					_socket.readBytes(response, 0, SERVER_HELLO_HEADER_LENGTH);
					maxBytesToRead -= SERVER_HELLO_HEADER_LENGTH;
					var helloToken:uint = response.readUnsignedByte(); // should be 0x02
					var helloLength:uint = getUInt24(response); // 3-byte length of hello data
					var sslMajorVersion:uint = response.readUnsignedByte(); // get major SSL version reported by server
					var sslMinorVersion:uint = response.readUnsignedByte(); // get minor SSL version reported by server
					response.position = 0; // seek to beginning of response
					_serverHelloStarted = true;
					_bytesToRead = helloLength - 2; // minus 2 because the SSL version bytes were part of the length
					if (helloToken == HANDSHAKE_TYPE_SERVER_HELLO) {
						debugPrint("ServerHello header found! (message type 0x" + helloToken.toString(16) + ")");
						debugPrint("ServerHello SSL version: " + sslMajorVersion + "." + sslMinorVersion);
						debugPrint("ServerHello length: " + helloLength);
					}
					else {
						debugPrint("Error: unknown TLS message header found! (0x" + helloToken.toString(16) + ")");
					}
				}
			}
			if (!_serverHelloEnded) {
				if (maxBytesToRead >= _bytesToRead) {
					_socket.readBytes(response, 0, _bytesToRead);
					maxBytesToRead -= _bytesToRead;
					response.position = 0; // seek to beginning of response after read
					_serverHelloEnded = true;
					_bytesToRead = 7; // length of Certificate message header
					
					debugPrint("Hello Recieved: 0x" + bytesToHexString(response));
					response.position = 0; // seek to beginning of response after read
					
					response.readBytes(_serverHelloData);
					response.position = 0 ; // seek to beginning of response after read
					parseServerHelloData(_serverHelloData);
				}
			}
			if (!_serverCertificateStarted) {
				if (maxBytesToRead >= _bytesToRead) {
					_socket.readBytes(response, 0, _bytesToRead);
					maxBytesToRead -= _bytesToRead;
					var certHandshakeToken:uint = response.readUnsignedByte(); // should be 0x0b
					var certHandshakeLength:uint = getUInt24(response); // 3-byte certificate handshake length
					var certLength:uint = getUInt24(response); // 3-byte certificate legnth
					response.position = 0;
					if (certHandshakeToken == HANDSHAKE_TYPE_CERTIFICATE) {
						_serverCertificateStarted = true;
						_bytesToRead = certLength;
						debugPrint("Certificate header found! (message type 0x" + certHandshakeToken.toString(16) + ")");
						debugPrint("Certificate length: " + certLength);
					}
					else {
						debugPrint("Error: unknown TLS message header found! (0x" + certHandshakeToken.toString(16) + ")");
					}
				}
			}
			if (!_serverCerificateEnded) {
				if (maxBytesToRead >= _bytesToRead) {
					_socket.readBytes(response, 0, _bytesToRead);
					maxBytesToRead -= _bytesToRead;
					_serverCerificateEnded = true;
					_bytesToRead = 0;
					response.readBytes(_serverCertificateData);
					response.position = 0 ;
					debugPrint("Read all certificate data");
					parseCertificateData(_serverCertificateData);
				}
			}
			
			if (maxBytesToRead == 0) {
				_tlsFrameStarted = false;
			}
		}
		
		private function parseServerHelloData(data:ByteArray):void {
			var b64:Base64Encoder = new Base64Encoder();
			b64.encodeBytes(data);
			_serverHelloString += b64.toString();
			debugPrint("SeverHelloData: " + _serverHelloString);
			return;
		}
		
		private function parseCertificateData(data:ByteArray):void {
			var certLength:uint = data.length;
			while (certLength > 0) {
				var currentCertLength:uint = getUInt24(data);
				certLength -= 3;
				var currentCert:ByteArray = new ByteArray();
				data.readBytes(currentCert, 0, currentCertLength);
				certLength -= currentCertLength;
				var b64:Base64Encoder = new Base64Encoder();
				b64.encodeBytes(currentCert);
				var encodedCert:String = b64.toString();
				//ExternalInterface.call("postCertificate", test);
				_certChainString += "-----BEGIN CERTIFICATE-----\n" + encodedCert + "\n-----END CERTIFICATE-----\n";
			}
			//debugPrint("Certificate(s):\n" + _certChainString);
			_socket.close();
			var results:Object = { host:_currentHost, message:_certChainString };
			debugPrint("Dispatching DONE event");
			dispatchEvent(new CrawlerEvent(CrawlerEvent.CRAWL_DONE, results));
		}
		
		private function getUInt24(data:ByteArray):uint {
			var uint24P1:uint = data.readUnsignedShort();
			var uint24P2:uint = data.readUnsignedByte();
			var uint24:uint = uint24P1 * 256 + uint24P2;
			return uint24;
		}
		
		protected function onSocketSecurity(e:SecurityErrorEvent):void {
			debugPrint("Security Error: " + e.text);
			var results:Object = { host:_currentHost, message:e.text };
			dispatchEvent(new CrawlerEvent(CrawlerEvent.CRAWL_ERROR, results));
			return;
		}
		
		protected function onSocketError(e:IOErrorEvent):void {
			debugPrint("Socket Error: " + e.text);
			var results:Object = { host:_currentHost, message:e.text };
			dispatchEvent(new CrawlerEvent(CrawlerEvent.CRAWL_ERROR, results));
			return;
		}
	}

}