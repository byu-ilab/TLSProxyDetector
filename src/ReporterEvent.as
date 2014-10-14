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
	import flash.events.Event;
	/**
	 * @author Mark O'Neill
	 */
	public class ReporterEvent extends Event
	{
		public static const REPORT_SENT:String = "report sent";
		public var result:Object;
		
		public function ReporterEvent(type:String, result:Object, bubbles:Boolean=false, cancelable:Boolean=false) {
			super(type, bubbles, cancelable);
			this.result = result;
		}
		
		public override function clone():Event {
			return new ReporterEvent(type, result, bubbles, cancelable);
		}
	}

}