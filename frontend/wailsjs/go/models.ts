export namespace pcap {
	
	export class InterfaceAddress {
	    IP: number[];
	    Netmask: number[];
	    Broadaddr: number[];
	    P2P: number[];
	
	    static createFrom(source: any = {}) {
	        return new InterfaceAddress(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.IP = source["IP"];
	        this.Netmask = source["Netmask"];
	        this.Broadaddr = source["Broadaddr"];
	        this.P2P = source["P2P"];
	    }
	}
	export class Interface {
	    Name: string;
	    Description: string;
	    Flags: number;
	    Addresses: InterfaceAddress[];
	
	    static createFrom(source: any = {}) {
	        return new Interface(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Name = source["Name"];
	        this.Description = source["Description"];
	        this.Flags = source["Flags"];
	        this.Addresses = this.convertValues(source["Addresses"], InterfaceAddress);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

