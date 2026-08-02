export namespace main {
	
	export class AppConfigDTO {
	    outputDir: string;
	
	    static createFrom(source: any = {}) {
	        return new AppConfigDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.outputDir = source["outputDir"];
	    }
	}
	export class BuildInfo {
	    mode: string;
	    version: string;
	
	    static createFrom(source: any = {}) {
	        return new BuildInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mode = source["mode"];
	        this.version = source["version"];
	    }
	}
	export class CommercialQuotaDTO {
	    unlimited: boolean;
	    charsUsed: number;
	    maxChars: number;
	    remaining: number;
	
	    static createFrom(source: any = {}) {
	        return new CommercialQuotaDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.unlimited = source["unlimited"];
	        this.charsUsed = source["charsUsed"];
	        this.maxChars = source["maxChars"];
	        this.remaining = source["remaining"];
	    }
	}
	export class DialogueSpeaker {
	    key: number;
	    voiceId: string;
	    note: string;
	
	    static createFrom(source: any = {}) {
	        return new DialogueSpeaker(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.voiceId = source["voiceId"];
	        this.note = source["note"];
	    }
	}
	export class GenerateParams {
	    voiceId: string;
	    modelId: string;
	    languageCode: string;
	    speed: number;
	    stability: number;
	    similarityBoost: number;
	    style: number;
	    useSpeakerBoost: boolean;
	    text: string;
	    outputDir: string;
	    outputFilePrefix: string;
	    maxWorkers: number;
	    exportSrt: boolean;
	    paragraphMode: boolean;
	    speakers: DialogueSpeaker[];
	
	    static createFrom(source: any = {}) {
	        return new GenerateParams(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.voiceId = source["voiceId"];
	        this.modelId = source["modelId"];
	        this.languageCode = source["languageCode"];
	        this.speed = source["speed"];
	        this.stability = source["stability"];
	        this.similarityBoost = source["similarityBoost"];
	        this.style = source["style"];
	        this.useSpeakerBoost = source["useSpeakerBoost"];
	        this.text = source["text"];
	        this.outputDir = source["outputDir"];
	        this.outputFilePrefix = source["outputFilePrefix"];
	        this.maxWorkers = source["maxWorkers"];
	        this.exportSrt = source["exportSrt"];
	        this.paragraphMode = source["paragraphMode"];
	        this.speakers = this.convertValues(source["speakers"], DialogueSpeaker);
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
	export class LanguageOption {
	    code: string;
	    label: string;
	
	    static createFrom(source: any = {}) {
	        return new LanguageOption(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.code = source["code"];
	        this.label = source["label"];
	    }
	}
	export class SavedLoginPrefs {
	    email: string;
	    password: string;
	    saved: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SavedLoginPrefs(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.email = source["email"];
	        this.password = source["password"];
	        this.saved = source["saved"];
	    }
	}
	export class SavedVoice {
	    voiceId: string;
	    label: string;
	
	    static createFrom(source: any = {}) {
	        return new SavedVoice(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.voiceId = source["voiceId"];
	        this.label = source["label"];
	    }
	}

}

export namespace tts {
	
	export class JobResult {
	    id: number;
	    ok: boolean;
	    message: string;
	    output: string;
	
	    static createFrom(source: any = {}) {
	        return new JobResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.ok = source["ok"];
	        this.message = source["message"];
	        this.output = source["output"];
	    }
	}

}

