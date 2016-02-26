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
	import flash.net.Socket;
	import flash.events.Event;
	import flash.events.EventDispatcher;
	import flash.events.IOErrorEvent;
	import flash.events.ProgressEvent;
	import flash.events.SecurityErrorEvent;
	import flash.external.ExternalInterface;
	import flash.utils.ByteArray;
	import flash.utils.Endian;
	
	/**
	 * @author Mark O'Neill
	 */
	public class CertificateReporter extends EventDispatcher
	{
		private var _reportSocket:Socket;
		private var _debug:Boolean;
		private var _queriedHost:String;
		private var _certChain:String;
		private var _reportPath:String;
		private var _reportHost:String;
		private var _reportPort:uint;
		private var _reportSent:Boolean;
		
		public function CertificateReporter(queriedHost:String, certChain:String, reportHost:String, reportPort:uint, reportPath:String, debug:Boolean) {
			_debug = debug;
			_queriedHost = queriedHost;
			_certChain = certChain;
			_reportPath = reportPath;
			_reportSent = false;
			_reportHost = reportHost;
			_reportPort = reportPort;
			
			_reportSocket = new Socket();
			_reportSocket.addEventListener(Event.CONNECT, onSocketConnected);
			_reportSocket.addEventListener(IOErrorEvent.IO_ERROR, onSocketError);
			_reportSocket.addEventListener(SecurityErrorEvent.SECURITY_ERROR, onSocketSecurity);
			_reportSocket.addEventListener(ProgressEvent.SOCKET_DATA, onSocketData);
		}
		
		public function start():void {
			_reportSocket.connect(_reportHost, _reportPort);
			return;
		}
		
		private function debugPrint(message:String):void {
			if (!_debug) return;
			
			var wrappedMessage:String = "Reporter for " + _queriedHost + ": " + message;
			if (ExternalInterface.available) {
				ExternalInterface.call("console.log", wrappedMessage);
			}
			trace(wrappedMessage);
			return;
		}
		
		protected function onSocketSecurity(e:SecurityErrorEvent):void {
			debugPrint("Security Error: " + e.text);
			return;
		}
		
		protected function onSocketError(e:IOErrorEvent):void {
			debugPrint("Socket Error: " + e.text);
			return;
		}
		
		protected function onSocketConnected(e:Event):void {
			debugPrint("Reporting Socket connected");
			var postQuery:ByteArray = createReportingQuery();
			_reportSocket.writeBytes(postQuery);
			postQuery.position = 0; // reset seek pointer
			//debugPrint("Sending: " + postQuery.toString());
			_reportSocket.flush();
			_reportSent = true;
			debugPrint("Report Sent");
			dispatchEvent(new ReporterEvent(ReporterEvent.REPORT_SENT, null));
			_reportSocket.close();
			return;
		}
		
		protected function onSocketData(e:ProgressEvent):void {
			// Stuff here eventually
		}
		
		private function createReportingQuery():ByteArray {
			var query:ByteArray = new ByteArray();
			var data:ByteArray = new ByteArray();
			query.endian = Endian.BIG_ENDIAN;
			query.writeMultiByte("POST " + _reportPath + " HTTP/1.1\r\nhost:" + _reportHost + "\r\n", "UTF-8");
			query.writeMultiByte("Content-Type:application/x-www-form-urlencoded\r\n", "UTF-8");
			data.writeMultiByte("certificate=" + urlEncodeB64(_certChain), "UTF-8");
			data.writeMultiByte("&host=" + urlEncodeB64(_queriedHost), "UTF-8");
			query.writeMultiByte("Content-Length:" + data.length + "\r\n\r\n", "UTF-8");
			query.writeBytes(data);
			return query;
		}
		
		private function urlEncodeB64(b64:String):String {
			var encodedStr:String = "";
			encodedStr = quickReplace(b64, "+", "%2B");
			encodedStr = quickReplace(encodedStr, "/", "%2F");
			encodedStr = quickReplace(encodedStr, "=", "%3D");
			return encodedStr;
		}
		
		private function quickReplace(source:String, oldString:String, newString:String):String {
			return source.split(oldString).join(newString);
		}
	}

}