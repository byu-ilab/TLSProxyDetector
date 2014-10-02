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
	
	/**
	 * @author Mark O'Neill
	 */
	public class Main extends Sprite 
	{	
		// Global settings
		private const REPORTING_PORT:uint = 80;
		private const REPORTING_HOST:String = "tlsresearch.byu.edu";
		private const REPORTING_PATH:String = "/AdCampaignInfo.php";
		private const _debug:Boolean = true;
		
		public function Main():void {
			// List of hosts from which to obtain certificates
			var hostsToCheck:Array = new Array(
				{ name:"tlsresearch.byu.edu", port:443, pport: 80 }
				
				// Add more hosts to check as follows:
				// Make sure the host has a socket policy file and note the port its served on with "pport"
				//,{ name:"amazon.com", port:443, pport: 80 }
			);
			var crawlers:Array = new Array();
			for (var i:uint = 0; i < hostsToCheck.length; i++) {
				var host:Object = hostsToCheck[i];
				var newCrawler:CertificateCrawler = new CertificateCrawler(host, i, _debug);
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
			new CertificateReporter(hostname, certificateChain, REPORTING_HOST, REPORTING_PORT, REPORTING_PATH, _debug);
		}
	}
}