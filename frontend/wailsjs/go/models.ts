export namespace main {
	
	export class AccountInfo {
	    loggedIn: boolean;
	    skipped: boolean;
	    email: string;
	    domain: string;
	    planName: string;
	    transferEnable: number;
	    usedUp: number;
	    usedDown: number;
	    expire: string;
	    subId: string;
	    domainCheckedAt?: number;
	
	    static createFrom(source: any = {}) {
	        return new AccountInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.loggedIn = source["loggedIn"];
	        this.skipped = source["skipped"];
	        this.email = source["email"];
	        this.domain = source["domain"];
	        this.planName = source["planName"];
	        this.transferEnable = source["transferEnable"];
	        this.usedUp = source["usedUp"];
	        this.usedDown = source["usedDown"];
	        this.expire = source["expire"];
	        this.subId = source["subId"];
	        this.domainCheckedAt = source["domainCheckedAt"];
	    }
	}
	export class AppSettings {
	    theme: string;
	    uiMode: string;
	    socksPort: number;
	    httpPort: number;
	    autoStart: boolean;
	    allowLan: boolean;
	    muxEnabled: boolean;
	    coreType: string;
	    dnsServers: string;
	    minimizeToTray: boolean;
	    subUpdateHours: number;
	
	    static createFrom(source: any = {}) {
	        return new AppSettings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.theme = source["theme"];
	        this.uiMode = source["uiMode"];
	        this.socksPort = source["socksPort"];
	        this.httpPort = source["httpPort"];
	        this.autoStart = source["autoStart"];
	        this.allowLan = source["allowLan"];
	        this.muxEnabled = source["muxEnabled"];
	        this.coreType = source["coreType"];
	        this.dnsServers = source["dnsServers"];
	        this.minimizeToTray = source["minimizeToTray"];
	        this.subUpdateHours = source["subUpdateHours"];
	    }
	}
	export class CoreStatus {
	    running: boolean;
	    coreType: string;
	    coreVersion: string;
	    systemProxy: boolean;
	    routingMode: string;
	    upSpeed: string;
	    downSpeed: string;
	    totalUp: string;
	    totalDown: string;
	    activeNodeName: string;
	    activeNodeProto: string;
	    socksPort: number;
	    httpPort: number;
	    tunRunning: boolean;
	    tunnelMode: boolean;
	    busy: boolean;
	    coreState: string;
	    coreError: string;
	    corePortError: boolean;
	    coreDirectOnly: boolean;
	
	    static createFrom(source: any = {}) {
	        return new CoreStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.coreType = source["coreType"];
	        this.coreVersion = source["coreVersion"];
	        this.systemProxy = source["systemProxy"];
	        this.routingMode = source["routingMode"];
	        this.upSpeed = source["upSpeed"];
	        this.downSpeed = source["downSpeed"];
	        this.totalUp = source["totalUp"];
	        this.totalDown = source["totalDown"];
	        this.activeNodeName = source["activeNodeName"];
	        this.activeNodeProto = source["activeNodeProto"];
	        this.socksPort = source["socksPort"];
	        this.httpPort = source["httpPort"];
	        this.tunRunning = source["tunRunning"];
	        this.tunnelMode = source["tunnelMode"];
	        this.busy = source["busy"];
	        this.coreState = source["coreState"];
	        this.coreError = source["coreError"];
	        this.corePortError = source["corePortError"];
	        this.coreDirectOnly = source["coreDirectOnly"];
	    }
	}
	export class LogItem {
	    id: number;
	    time: string;
	    level: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new LogItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.time = source["time"];
	        this.level = source["level"];
	        this.message = source["message"];
	    }
	}
	export class NodeItem {
	    id: string;
	    name: string;
	    protocol: string;
	    address: string;
	    port: number;
	    uuid: string;
	    security: string;
	    network: string;
	    delay: number;
	    active: boolean;
	    group: string;
	    upload: string;
	    download: string;
	    subId?: string;
	    alterId?: number;
	    flow?: string;
	    sni?: string;
	    pbk?: string;
	    sid?: string;
	    fp?: string;
	    path?: string;
	    hostName?: string;
	    serviceName?: string;
	    method?: string;
	    username?: string;
	    insecure?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new NodeItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.protocol = source["protocol"];
	        this.address = source["address"];
	        this.port = source["port"];
	        this.uuid = source["uuid"];
	        this.security = source["security"];
	        this.network = source["network"];
	        this.delay = source["delay"];
	        this.active = source["active"];
	        this.group = source["group"];
	        this.upload = source["upload"];
	        this.download = source["download"];
	        this.subId = source["subId"];
	        this.alterId = source["alterId"];
	        this.flow = source["flow"];
	        this.sni = source["sni"];
	        this.pbk = source["pbk"];
	        this.sid = source["sid"];
	        this.fp = source["fp"];
	        this.path = source["path"];
	        this.hostName = source["hostName"];
	        this.serviceName = source["serviceName"];
	        this.method = source["method"];
	        this.username = source["username"];
	        this.insecure = source["insecure"];
	    }
	}
	export class SubscriptionItem {
	    id: string;
	    name: string;
	    nodeCount: number;
	    updatedAt: string;
	    autoCheck: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SubscriptionItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.nodeCount = source["nodeCount"];
	        this.updatedAt = source["updatedAt"];
	        this.autoCheck = source["autoCheck"];
	    }
	}
	export class UpdateInfo {
	    currentVersion: string;
	    latestVersion: string;
	    hasUpdate: boolean;
	    isDev: boolean;
	    notes: string;
	    publishedAt: string;
	    releaseUrl: string;
	    assetSize: number;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new UpdateInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.currentVersion = source["currentVersion"];
	        this.latestVersion = source["latestVersion"];
	        this.hasUpdate = source["hasUpdate"];
	        this.isDev = source["isDev"];
	        this.notes = source["notes"];
	        this.publishedAt = source["publishedAt"];
	        this.releaseUrl = source["releaseUrl"];
	        this.assetSize = source["assetSize"];
	        this.message = source["message"];
	    }
	}
	export class UpdateProgress {
	    stage: string;
	    percent: number;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new UpdateProgress(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.stage = source["stage"];
	        this.percent = source["percent"];
	        this.message = source["message"];
	    }
	}

}

