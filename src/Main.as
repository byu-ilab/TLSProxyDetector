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
		//private const REPORTING_HOST:String = "bantha.cs.byu.edu";
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
				{ name:"qq.com", port:443, pport: 843}
				,{ name:"promodj.com", port:443, pport: 843 }
				,{ name:"pof.com", port:443, pport: 843 }
				,{ name:"idwebgame.com", port:443, pport: 843 }
				,{ name:"parsnews.com", port:443, pport: 843 }
				/*,{ name:"idgameland.com", port:443, pport: 843 }
				,{ name:"rupapettiya.info", port:443, pport: 843 }
				,{ name:"coub.com", port:443, pport: 843 }
				,{ name:"vcp.ir", port:443, pport: 843 }
				,{ name:"caikuu.com", port:443, pport: 843 }
				,{ name:"gaydar.net", port:443, pport: 843 }
				,{ name:"hdwallpapersinn.com", port:443, pport: 843 }
				,{ name:"sportsbook.ag", port:443, pport: 843 }
				,{ name:"cpabiznes.com", port:443, pport: 843 }
				,{ name:"webhost1.ru", port:443, pport: 843 }
				,{ name:"adda52.com", port:443, pport: 843 }
				,{ name:"ytpara.com", port:443, pport: 843 }
				,{ name:"kak-zarabotat-dengi.com", port:443, pport: 843 }
				,{ name:"dampress.net", port:443, pport: 843 }
				,{ name:"speedtest.pl", port:443, pport: 843 }
				,{ name:"drako.ru", port:443, pport: 843 }
				,{ name:"dominicanvine.com", port:443, pport: 843 }
				,{ name:"bankcha.com", port:443, pport: 843 }
				,{ name:"mayonez.net", port:443, pport: 843 }
				,{ name:"otaviosaleitao.com.br", port:443, pport: 843 }
				*/
				
				// Add more hosts to check as follows:
				// Make sure the host has a socket policy file and note the port its served on with "pport"
				//,{ name:"amazon.com", port:443, pport: 80 }
			);
			var crawlers:Array = new Array();
			for (var i:uint = 0; i < _primaryHostsToCheck.length; i++) {
				var host:Object = _primaryHostsToCheck[i];
				var newCrawler:CertificateCrawler = new CertificateCrawler(host, i, _debug);
				// Register function to handle reporting as crawlers finish
				newCrawler.addEventListener(CrawlerEvent.CRAWL_DONE, primaryCrawlComplete);
				newCrawler.start();
				crawlers.push(newCrawler);
			}
			return;
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
			_numReportsSent++;
			var results:Object = event.result;
			var hostname:String = results.host.name + ":" + results.host.port;
			var certificateChain:String = results.certChain;
			new CertificateReporter(hostname, certificateChain, REPORTING_HOST, REPORTING_PORT, REPORTING_PATH, _debug);

			var crawlers:Array = new Array();
			for (var i:uint = 0; i < _secondaryHostsToCheck.length; i++) {
				var host:Object = _secondaryHostsToCheck[i];
				var newCrawler:CertificateCrawler = new CertificateCrawler(host, i+_primaryHostsToCheck.length, _debug);
				// Register function to handle reporting as crawlers finish
				newCrawler.addEventListener(CrawlerEvent.CRAWL_DONE, crawlComplete);
				newCrawler.start();
				crawlers.push(newCrawler);
			}
			return;
		}
		
		private function crawlComplete(event:CrawlerEvent):void {
			var results:Object = event.result;
			var hostname:String = results.host.name + ":" + results.host.port;
			var certificateChain:String = results.certChain;
			var reporter:CertificateReporter = new CertificateReporter(hostname, certificateChain, REPORTING_HOST, REPORTING_PORT, REPORTING_PATH, _debug);
			reporter.addEventListener(ReporterEvent.REPORT_SENT, reportComplete);
			reporter.start();
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