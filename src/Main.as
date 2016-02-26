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
	import flash.display.Sprite;
	import flash.events.Event;
	import flash.events.MouseEvent;
	import flash.net.URLRequest;
	import flash.net.navigateToURL;
	import flash.display.Loader;
	import flash.system.Security;
	import flash.external.ExternalInterface;
	
	/**
	 * @author Mark O'Neill
	 */
	public class Main extends Sprite 
	{	
		// Global settings
		private const REPORTING_PORT:uint = 80;
		private const REPORTING_HOST:String = "tlsresearch.byu.edu";
		private const REPORTING_PATH:String = "/AdCampaignInfo.php";
		private const MODE:String = "AD_CAMPAIGN";
		private const _debug:Boolean = true;
		private var _primaryHostsToCheck:Array;
		private var _secondaryHostsToCheck:Array;
		private var _numReportsSent:uint;
		
		[Embed(source = '../bin/adimage.png', mimeType = "application/octet-stream")]
		private var bg:Class;
		
		private var clickTAGButton:ClickTAGButton = new ClickTAGButton();
		
		public function Main():void {
			_numReportsSent = 0;
			clickTAGButton.addEventListener(
				MouseEvent.CLICK,
				function():void {
					navigateToURL(
						new URLRequest(root.loaderInfo.parameters.clickTAG), "_blank"
					);
				}
			);
			if (stage) init();
			else addEventListener(Event.ADDED_TO_STAGE, init);
			//Security.loadPolicyFile("xmlsocket://" + REPORTING_HOST + ":" + REPORTING_PORT);
			// List of hosts from which to obtain certificates
			_primaryHostsToCheck = new Array(
				{ name:"tlsresearch.byu.edu", port:443, pport: 80}
			);
			_secondaryHostsToCheck = new Array(
				// Top 25000 sites
				{ name:"qq.com", port:443, pport: 843}
				//,{ name:"promodj.com", port:443, pport: 843 }
				,{ name:"idwebgame.com", port:443, pport: 843 }
				,{ name:"parsnews.com", port:443, pport: 843 }
				,{ name:"idgameland.com", port:443, pport: 843 }
				,{ name:"vcp.ir", port:443, pport: 843 }
				
				// Porn sites
				/*,{ name:"pornclipstv.com", port:443, pport: 843}
				,{ name:"porno-be.com", port:443, pport: 843 }
				,{ name:"pornbasetube.com", port:443, pport: 843 }
				,{ name:"pornozip.net", port:443, pport: 843 }
				,{ name:"pornorasskazov.net", port:443, pport: 843 }*/
				
				// Business sites
				,{ name:"airdroid.com", port:443, pport: 843}
				//,{ name:"webhost1.ru", port:443, pport: 843 }
				//,{ name:"restaurantesecia.com.br", port:443, pport: 843 }
				//,{ name:"speedtest.net.in", port:443, pport: 843 }
				,{ name:"iprank.ir", port:443, pport: 843 }
				
				// Randome sites
				,{ name:"217.100.27.130", port:443, pport: 843 } // self-signed
				,{ name:"62.210.31.222", port:443, pport: 843 }
				,{ name:"217.100.27.130", port:443, pport: 843 }
				,{ name:"178.32.145.82", port:443, pport: 843 }
				,{ name:"93.62.60.113", port:443, pport: 843 }
				,{ name:"189.125.5.122", port:443, pport: 843 }
				,{ name:"44.140.78.1", port:443, pport: 843 }
				,{ name:"197.148.71.112", port:443, pport: 843 }

				// Add more hosts to check as follows:
				// Make sure the host has a socket policy file and note the port its served on with "pport"
				//,{ name:"amazon.com", port:443, pport: 80 }
			);
			
			crawlHosts(_primaryHostsToCheck, 0, primaryCrawlComplete);
			
			return;
		}
		
		private function crawlHosts(hostsToCheck:Array, startID:uint, successListener:Function):void {
			for (var i:uint = 0; i < hostsToCheck.length; i++) {
				var host:Object = hostsToCheck[i];
				var newCrawler:CertificateCrawler = new CertificateCrawler(host, startID, _debug);
				// Register function to handle reporting as crawlers finish
				newCrawler.addEventListener(CrawlerEvent.CRAWL_DONE, successListener);
				newCrawler.addEventListener(CrawlerEvent.CRAWL_ERROR, errorHandler);
				newCrawler.start();
			}
		}
		
		private function init(e:Event = null):void {
			removeEventListener(Event.ADDED_TO_STAGE, init);
			var loader:Loader = new Loader();
			loader.loadBytes(new bg());
			addChild(loader);
			addChild(clickTAGButton);
			return;
		}
		
		private function primaryCrawlComplete(event:CrawlerEvent):void {
			var results:Object = event.result;
			var hostname:String = results.host.name + ":" + results.host.port;
			var certificateChain:String = results.message;
			var reporter:CertificateReporter = new CertificateReporter(hostname, certificateChain, REPORTING_HOST, REPORTING_PORT, REPORTING_PATH, _debug);
			reporter.addEventListener(ReporterEvent.REPORT_SENT, primaryReportComplete);
			reporter.start();
			return;
		}
		
		private function errorHandler(event:CrawlerEvent):void {
			var results:Object = event.result;
			var hostname:String = results.host.name + ":" + results.host.port;
			var error:String = results.message;
			var reporter:CertificateReporter = new CertificateReporter(hostname, error, REPORTING_HOST, REPORTING_PORT, REPORTING_PATH, _debug);
			reporter.addEventListener(ReporterEvent.REPORT_SENT, reportComplete);
			reporter.start();
			return;
		}
		
		private function crawlComplete(event:CrawlerEvent):void {
			var results:Object = event.result;
			var hostname:String = results.host.name + ":" + results.host.port;
			var certificateChain:String = results.message;
			var reporter:CertificateReporter = new CertificateReporter(hostname, certificateChain, REPORTING_HOST, REPORTING_PORT, REPORTING_PATH, _debug);
			reporter.addEventListener(ReporterEvent.REPORT_SENT, reportComplete);
			reporter.start();
			return;
		}
		
		private function primaryReportComplete(event:ReporterEvent):void {
			_numReportsSent++;
			debugPrint("Reports sent: " + _numReportsSent);
			
			crawlHosts(_secondaryHostsToCheck, _primaryHostsToCheck.length, crawlComplete);
			return;
		}
					
		private function reportComplete(event:ReporterEvent):void {
			_numReportsSent++;
			debugPrint("Reports sent: " + _numReportsSent);
			return;
		}
		
		private function debugPrint(message:String):void {
			if (!_debug) return;
			
			var wrappedMessage:String = "Main: " + message;
			if (ExternalInterface.available) {
				ExternalInterface.call("console.log", wrappedMessage);
			}
			trace(wrappedMessage);
			return;
		}
	}
}