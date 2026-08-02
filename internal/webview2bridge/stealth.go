package webview2bridge

// stealthScript — "smart stealth": chỉ override giá trị KHI giá trị gốc
// bất thường (SwiftShader, cores<2, plugins=0, webdriver=true…).
// KHÔNG OVERRIDE khi giá trị đã OK → hCaptcha không phát hiện monkey-patch.
//
// Nguyên tắc:
//   - KHÔNG patch Function.prototype.toString (detection vector #1)
//   - KHÔNG replace prototype methods khi giá trị gốc đã hợp lệ
//   - Chỉ dùng Object.defineProperty trên instance (ít bị detect hơn prototype)
//   - Mỗi patch wrapped trong try/catch riêng → 1 lỗi không ảnh hưởng cái khác
const stealthScript = `
(function() {

	// ---- 1. navigator.webdriver — chỉ override nếu đang là true ----
	try {
		if (navigator.webdriver === true) {
			Object.defineProperty(navigator, 'webdriver', {
				get: function() { return false; },
				configurable: true
			});
		}
	} catch(e) {}

	// ---- 2. WebGL renderer — chỉ hook nếu là SwiftShader/llvmpipe/VM ----
	try {
		var _testC = document.createElement('canvas');
		var _testGl = _testC.getContext('webgl') || _testC.getContext('experimental-webgl');
		if (_testGl) {
			var _testDbg = _testGl.getExtension('WEBGL_debug_renderer_info');
			if (_testDbg) {
				var _realRenderer = _testGl.getParameter(_testDbg.UNMASKED_RENDERER_WEBGL) || '';
				var _realVendor = _testGl.getParameter(_testDbg.UNMASKED_VENDOR_WEBGL) || '';
				var _needPatch = /swiftshader|llvmpipe|software|microsoft basic|vmware|virtualbox|parallels/i.test(_realRenderer + ' ' + _realVendor);

				if (_needPatch) {
					// Danh sách GPU phổ biến để random — tránh tất cả worker cùng 1 GPU
					var _gpus = [
						{v:'Google Inc. (NVIDIA)', r:'ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)'},
						{v:'Google Inc. (NVIDIA)', r:'ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 6GB Direct3D11 vs_5_0 ps_5_0, D3D11)'},
						{v:'Google Inc. (NVIDIA)', r:'ANGLE (NVIDIA, NVIDIA GeForce RTX 2060 Direct3D11 vs_5_0 ps_5_0, D3D11)'},
						{v:'Google Inc. (AMD)',    r:'ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)'},
						{v:'Google Inc. (AMD)',    r:'ANGLE (AMD, AMD Radeon RX 570 Direct3D11 vs_5_0 ps_5_0, D3D11)'},
						{v:'Google Inc. (Intel)',  r:'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)'},
						{v:'Google Inc. (Intel)',  r:'ANGLE (Intel, Intel(R) Iris Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)'}
					];
					var _pick = _gpus[Math.floor(Math.random() * _gpus.length)];

					var _origGetParam = WebGLRenderingContext.prototype.getParameter;
					WebGLRenderingContext.prototype.getParameter = function(p) {
						if (p === 0x9245) return _pick.v;
						if (p === 0x9246) return _pick.r;
						return _origGetParam.call(this, p);
					};
					if (typeof WebGL2RenderingContext !== 'undefined') {
						var _origGetParam2 = WebGL2RenderingContext.prototype.getParameter;
						WebGL2RenderingContext.prototype.getParameter = function(p) {
							if (p === 0x9245) return _pick.v;
							if (p === 0x9246) return _pick.r;
							return _origGetParam2.call(this, p);
						};
					}
				}
			}
		}
		_testC = null; _testGl = null;
	} catch(e) {}

	// ---- 3. navigator.plugins — chỉ fake nếu plugins trống (headless/VM) ----
	try {
		if (navigator.plugins.length === 0) {
			var _fp = [
				{name:'Chrome PDF Plugin', description:'Portable Document Format', filename:'internal-pdf-viewer', length:1},
				{name:'Chrome PDF Viewer', description:'', filename:'mhjfbmdgcfjbbpaeojofohoefgiehjai', length:1},
				{name:'Native Client', description:'', filename:'internal-nacl-plugin', length:1}
			];
			_fp.item = function(i){return this[i]||null;};
			_fp.namedItem = function(n){for(var j=0;j<this.length;j++){if(this[j].name===n)return this[j];}return null;};
			_fp.refresh = function(){};
			Object.defineProperty(navigator, 'plugins', {get:function(){return _fp;}, configurable:true});
		}
	} catch(e) {}

	// ---- 4. chrome.runtime — chỉ mock nếu window.chrome tồn tại mà runtime thiếu ----
	try {
		if (typeof window.chrome !== 'undefined' && typeof window.chrome.runtime === 'undefined') {
			window.chrome.runtime = {
				connect: function(){return{onMessage:{addListener:function(){}},postMessage:function(){},disconnect:function(){},onDisconnect:{addListener:function(){}}};},
				sendMessage: function(){},
				id: undefined,
				onMessage:{addListener:function(){},removeListener:function(){},hasListener:function(){return false;}},
				onConnect:{addListener:function(){},removeListener:function(){},hasListener:function(){return false;}}
			};
		}
	} catch(e) {}

	// ---- 5. hardwareConcurrency — chỉ override nếu quá thấp (VM signal) ----
	try {
		if (navigator.hardwareConcurrency < 2) {
			var _fakeC = 2 + Math.floor(Math.random() * 5); // 2-6
			Object.defineProperty(navigator, 'hardwareConcurrency', {get:function(){return _fakeC;}, configurable:true});
		}
	} catch(e) {}

	// ---- 6. deviceMemory — chỉ override nếu quá thấp ----
	try {
		if (navigator.deviceMemory && navigator.deviceMemory < 2) {
			Object.defineProperty(navigator, 'deviceMemory', {get:function(){return 8;}, configurable:true});
		}
	} catch(e) {}

	// ---- 7. navigator.languages — chỉ set nếu trống ----
	try {
		if (!navigator.languages || navigator.languages.length === 0) {
			Object.defineProperty(navigator, 'languages', {get:function(){return ['en-US','en'];}, configurable:true});
		}
	} catch(e) {}

	// ---- 8. window.outerWidth/Height — chỉ fix nếu = 0 (headless artifact) ----
	try {
		if (window.outerWidth === 0) {
			Object.defineProperty(window, 'outerWidth', {get:function(){return window.innerWidth||1920;}});
		}
		if (window.outerHeight === 0) {
			Object.defineProperty(window, 'outerHeight', {get:function(){return window.innerHeight||1080;}});
		}
	} catch(e) {}

	// ---- 9. Permissions API — normalize notifications (giảm noise) ----
	try {
		if (navigator.permissions && navigator.permissions.query) {
			var _origQ = navigator.permissions.query.bind(navigator.permissions);
			navigator.permissions.query = function(desc) {
				if (desc && desc.name === 'notifications') {
					return Promise.resolve({state: Notification.permission || 'prompt', onchange: null});
				}
				return _origQ(desc);
			};
		}
	} catch(e) {}

})();
`
