'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require poll';
'require view.passwall.tools as pw';

var APP = 'passwall';

var FALLBACK = [
	{ key: 'geoview', name: 'Geoview', default_path: '/usr/bin/geoview' },
	{ key: 'chinadns-ng', name: 'ChinaDNS-NG', default_path: '/usr/bin/chinadns-ng' },
	{ key: 'xray', name: 'Xray', default_path: '/usr/bin/xray' },
	{ key: 'sing-box', name: 'Sing-Box', default_path: '/usr/bin/sing-box' },
	{ key: 'hysteria', name: 'Hysteria', default_path: '/usr/bin/hysteria' }
];

function ensureSection(type) {
	var id = pw.sectionId(APP, type);
	if (!id)
		id = uci.add(APP, type);
	return id;
}

function paintHtml(root) {
	if (!root || !root.querySelectorAll)
		return;
	root.querySelectorAll('.cbi-value-description, .cbi-section-descr, .cbi-map-descr').forEach(function(el) {
		var text = el.textContent || '';
		if (text.indexOf('<') === -1)
			return;
		el.innerHTML = text;
	});
}

function formatVersion(value) {
	return String(value || '').trim().replace(/-r([0-9]+)$/, '-$1');
}

function asObject(res) {
	if (res && typeof res === 'object' && typeof res.output === 'string') {
		var text = res.output.trim();
		if (!text)
			return res;
		try {
			return JSON.parse(text);
		}
		catch (e) {
			return res;
		}
	}
	if (typeof res === 'string') {
		try {
			return JSON.parse(res);
		}
		catch (e2) {
			return { code: 1, error: res };
		}
	}
	return res || {};
}

function componentsOf(caps) {
	var src = (caps && Array.isArray(caps.components) && caps.components.length) ? caps.components : FALLBACK;
	var list = [];
	src.forEach(function(item) {
		if (!item)
			return;
		var key = item.key || '';
		if (!key && item.name) {
			FALLBACK.forEach(function(fb) {
				if (fb.name === item.name)
					key = fb.key;
			});
		}
		if (!key)
			return;
		var fallback = null;
		FALLBACK.forEach(function(fb) {
			if (fb.key === key)
				fallback = fb;
		});
		list.push({
			key: key,
			name: item.name || (fallback ? fallback.name : key),
			default_path: item.default_path || (fallback ? fallback.default_path : ('/usr/bin/' + key))
		});
	});
	return list.length ? list : FALLBACK.slice();
}

function checkCall(app) {
	if (app === APP)
		return pw.call('app_check');
	if (app === 'geoview')
		return pw.call('check_geoview');
	if (app === 'chinadns-ng')
		return pw.call('check_chinadns-ng');
	if (app === 'xray')
		return pw.call('check_xray');
	if (app === 'sing-box')
		return pw.call('check_sing-box');
	if (app === 'hysteria')
		return pw.call('check_hysteria');
	return pw.call('com_check', { com: app });
}

function updateCall(app, args) {
	args = args || {};
	if (app === APP)
		return pw.call('app_update', args);
	if (app === 'geoview')
		return pw.call('update_geoview', args);
	if (app === 'chinadns-ng')
		return pw.call('update_chinadns-ng', args);
	if (app === 'xray')
		return pw.call('update_xray', args);
	if (app === 'sing-box')
		return pw.call('update_sing-box', args);
	if (app === 'hysteria')
		return pw.call('update_hysteria', args);
	var payload = { com: app };
	Object.keys(args).forEach(function(key) {
		if (args[key] != null)
			payload[key] = args[key];
	});
	return pw.call('com_update', payload);
}

function versionCall(com) {
	if (com === 'geoview')
		return pw.call('version_geoview');
	if (com === 'chinadns-ng')
		return pw.call('version_chinadns-ng');
	if (com === 'xray')
		return pw.call('version_xray');
	if (com === 'sing-box')
		return pw.call('version_sing-box');
	if (com === 'hysteria')
		return pw.call('version_hysteria');
	return pw.call('com_version', { com: com });
}

function versionBlock(localVersion, comps) {
	var state = {
		info: {},
		inProgress: 0,
		componentUpdates: 0,
		luciUpdating: false
	};
	var checkText = _('Check update');
	var forceText = _('Force update');
	var retryText = _('Retry');
	var latestText = _('It is the latest version');
	var successText = _('Update successful');
	var clickText = _('Click to update');
	var updatingText = _('Updating...');
	var closeText = _('Updating, are you sure to close?');
	var downloadingText = _('Downloading...');
	var unpackingText = _('Unpacking...');
	var movingText = _('Moving...');
	var installingText = _('Installing...');
	var installingNotice = _('Do not refresh or switch pages during installation.');
	var failedText = _('Update failed');
	var unknownText = _('Unknown error');

	function buttons() {
		return document.querySelectorAll('#app_version input[data-update-app]');
	}

	function syncButtons() {
		Array.prototype.forEach.call(buttons(), function(btn) {
			btn.disabled = !!btn.updateDisabled || state.luciUpdating ||
				(btn.getAttribute('data-update-app') === APP && state.componentUpdates > 0);
		});
	}

	function setDisabled(btn, disabled) {
		btn.updateDisabled = disabled;
		syncButtons();
	}

	function addNotice() {
		if (state.inProgress === 0) {
			window.onbeforeunload = function(e) {
				e.returnValue = closeText;
				return closeText;
			};
		}
		state.inProgress++;
	}

	function removeNotice(app) {
		if (app === APP)
			state.luciUpdating = false;
		else if (app)
			state.componentUpdates--;
		state.inProgress--;
		syncButtons();
		if (state.inProgress <= 0) {
			state.inProgress = 0;
			window.onbeforeunload = undefined;
		}
	}

	function detailOf(btn) {
		var app = btn.getAttribute('data-update-app');
		var id = app === APP ? (APP + '-check_btn') : ('_' + app + '-check_btn');
		return document.getElementById(id + '-detail');
	}

	function onSuccess(btn) {
		if (btn) {
			btn.value = successText;
			btn.placeholder = successText;
			setDisabled(btn, true);
		}
		if (state.inProgress === 0) {
			window.setTimeout(function() {
				if (state.inProgress === 0 && !state.luciUpdating)
					window.location.reload();
			}, 1000);
		}
	}

	function onError(btn, message, checking) {
		setDisabled(btn, false);
		btn.value = retryText;
		var app = btn.getAttribute('data-update-app');
		var detail = detailOf(btn);
		if (app === APP && !checking)
			message = message ? failedText : unknownText;
		if (message && detail)
			detail.textContent = message;
	}

	function showRemote(btn, json) {
		var detail = document.getElementById(btn.id + '-detail');
		if (!detail)
			return;
		while (detail.firstChild)
			detail.removeChild(detail.firstChild);
		if (!json.remote_version)
			return;
		var label = E('em', { 'style': 'color:red' }, String(json.remote_version));
		if (json.html_url && /^https?:\/\//i.test(String(json.html_url)))
			detail.appendChild(E('a', { 'href': String(json.html_url), 'target': '_blank' }, [ label ]));
		else
			detail.appendChild(label);
	}

	function checkUpdate(btn, app) {
		setDisabled(btn, true);
		btn.value = updatingText;
		addNotice();
		var detail = document.getElementById(btn.id + '-detail');
		if (detail)
			detail.textContent = '';
		checkCall(app).then(function(res) {
			removeNotice();
			var json = asObject(res);
			if (!json || json.code) {
				delete state.info[app];
				onError(btn, json && json.error, true);
				return;
			}
			state.info[app] = json;
			if (json.has_update) {
				setDisabled(btn, false);
				btn.value = clickText;
				btn.placeholder = clickText;
				showRemote(btn, json);
			}
			else {
				setDisabled(btn, true);
				btn.value = latestText;
				var forceBtn = document.getElementById('_' + app + '-force_btn');
				if (forceBtn)
					forceBtn.style.display = 'inline';
			}
		}).catch(function(err) {
			removeNotice();
			delete state.info[app];
			onError(btn, (err && err.message) || _('Unexpected error'), true);
		});
	}

	function moveFile(btn, app, file) {
		btn.value = movingText;
		updateCall(app, {
			task: 'move',
			file: file
		}).then(function(res) {
			removeNotice(app);
			var json = asObject(res);
			if (!json || json.code)
				onError(btn, json && json.error);
			else
				onSuccess(btn);
		}).catch(function(err) {
			removeNotice(app);
			onError(btn, err && err.message);
		});
	}

	function installLuci(btn, downloadId) {
		btn.value = installingText;
		var detail = document.getElementById(APP + '-check_btn-detail');
		if (detail)
			detail.textContent = installingNotice;
		var pending = false;
		var finished = false;
		var timer = window.setInterval(function() {
			if (pending)
				return;
			pending = true;
			var xhr = new XMLHttpRequest();
			xhr.open('GET', L.resource(APP + '-update/' + downloadId + '.json') + '?_=' + Date.now(), true);
			xhr.timeout = 5000;
			xhr.onerror = xhr.ontimeout = function() {
				pending = false;
			};
			xhr.onload = function() {
				pending = false;
				if (finished)
					return;
				var json;
				try {
					json = JSON.parse(xhr.responseText);
				}
				catch (e) {
					return;
				}
				if (typeof json.code !== 'number')
					return;
				finished = true;
				window.clearInterval(timer);
				removeNotice(APP);
				if (json.code)
					onError(btn, failedText);
				else {
					window.onbeforeunload = undefined;
					window.location.reload();
				}
			};
			xhr.send();
		}, 1000);
		var info = state.info[APP] || {};
		updateCall(APP, {
			task: 'install',
			id: downloadId,
			force: info.has_update ? '0' : '1'
		}).then(function(res) {
			var json = asObject(res);
			if (!finished && json && json.code) {
				finished = true;
				window.clearInterval(timer);
				removeNotice(APP);
				onError(btn, failedText);
			}
		}).catch(function(err) {
			if (finished)
				return;
			finished = true;
			window.clearInterval(timer);
			removeNotice(APP);
			onError(btn, (err && err.message) || failedText);
		});
	}

	function doUpdate(btn, app) {
		if (state.luciUpdating || (app === APP && state.componentUpdates > 0))
			return;
		var appInfo = state.info[app];
		if (!appInfo || !appInfo.data) {
			onError(btn, _('Unexpected error'), true);
			return;
		}
		if (app === APP)
			state.luciUpdating = true;
		else
			state.componentUpdates++;
		setDisabled(btn, true);
		btn.value = downloadingText;
		addNotice();

		var downloadId = Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
		var totalSize = Number(appInfo.data.size) || 0;
		if (app === APP)
			totalSize += Number(appInfo.i18n && appInfo.i18n.size) || 0;
		if (!isFinite(totalSize) || totalSize <= 0)
			totalSize = 0;
		var active = true;
		var pending = false;
		var progressTimer = null;

		function stopProgress() {
			active = false;
			if (progressTimer) {
				window.clearInterval(progressTimer);
				progressTimer = null;
			}
		}

		function pollProgress() {
			if (!active || pending || totalSize <= 0)
				return;
			pending = true;
			updateCall(app, {
				task: 'progress',
				id: downloadId,
				total_size: totalSize
			}).then(function(res) {
				pending = false;
				var json = asObject(res);
				if (active && json && !json.code && typeof json.percent === 'number')
					btn.value = downloadingText + ' ' + json.percent + '%';
			}).catch(function() {
				pending = false;
			});
		}

		if (totalSize > 0) {
			pollProgress();
			progressTimer = window.setInterval(pollProgress, 1000);
		}

		function download(part) {
			var asset = (app === APP && part === 2) ? appInfo.i18n : appInfo.data;
			if (!asset || !asset.browser_download_url) {
				stopProgress();
				removeNotice(app);
				onError(btn, failedText);
				return;
			}
			var size = (app === APP && part === 1) ? totalSize : (Number(asset.size) || 0);
			var fields = {
				url: asset.browser_download_url,
				size: size / 1024,
				id: downloadId
			};
			if (app === APP)
				fields.part = String(part);
			updateCall(app, fields).then(function(res) {
				var json = asObject(res);
				if (json && !json.code && app === APP && part === 1) {
					download(2);
					return;
				}
				stopProgress();
				if (!json || json.code) {
					removeNotice(app);
					onError(btn, json && (json.error || failedText));
				}
				else if (app === APP) {
					installLuci(btn, downloadId);
				}
				else if (json.zip) {
					btn.value = unpackingText;
					updateCall(app, {
						task: 'extract',
						file: json.file,
						subfix: appInfo.type || ''
					}).then(function(extracted) {
						var body = asObject(extracted);
						if (!body || body.code) {
							removeNotice(app);
							onError(btn, body && body.error);
						}
						else {
							moveFile(btn, app, body.file);
						}
					}).catch(function(err) {
						removeNotice(app);
						onError(btn, err && err.message);
					});
				}
				else {
					moveFile(btn, app, json.file);
				}
			}).catch(function(err) {
				stopProgress();
				removeNotice(app);
				onError(btn, (err && err.message) || failedText);
			});
		}

		download(1);
	}

	function onClick(btn, app) {
		if (state.info[app] === undefined)
			checkUpdate(btn, app);
		else
			doUpdate(btn, app);
	}

	function row(title, versionNode, app, checkId, detailId) {
		return E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, title),
			E('div', { 'class': 'cbi-value-field' }, [
				E('span', {}, [ '【 ', versionNode, ' 】' ]),
				E('input', {
					'class': 'btn cbi-button cbi-button-apply',
					'type': 'button',
					'id': checkId,
					'data-update-app': app,
					'value': checkText,
					'click': function(ev) {
						onClick(ev.target, app);
					}
				}),
				E('input', {
					'class': 'btn cbi-button cbi-button-apply',
					'type': 'button',
					'id': '_' + app + '-force_btn',
					'data-update-app': app,
					'value': forceText,
					'style': 'display:none',
					'click': function(ev) {
						doUpdate(ev.target, app);
					}
				}),
				E('span', { 'id': detailId })
			])
		]);
	}

	var rows = [
		row('Passwall ' + _('Version'), E('span', {}, formatVersion(localVersion)), APP, APP + '-check_btn', APP + '-check_btn-detail')
	];
	comps.forEach(function(comp) {
		var holder = E('span', { 'class': 'com_version', 'data-com': comp.key }, _('Collecting data...'));
		rows.push(row(comp.name + ' ' + _('Version'), holder, comp.key, '_' + comp.key + '-check_btn', '_' + comp.key + '-check_btn-detail'));
	});

	var root = E('div', { 'id': 'app_version' }, rows);
	window.setTimeout(function() {
		Array.prototype.forEach.call(root.querySelectorAll('.com_version'), function(el) {
			var key = el.getAttribute('data-com');
			versionCall(key).then(function(res) {
				var json = asObject(res);
				if (json && (json.code == 1 || json.code === '1')) {
					var data = json.data;
					el.textContent = (data != null && data !== '') ? String(data) : _('Null');
				}
			}).catch(function() {});
		});
	}, 0);
	return root;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(APP),
			pw.loadCaps().catch(function() { return {}; }),
			pw.readText('/tmp/etc/passwall_tmp/passwall_version')
		]);
	},

	render: function(data) {
		var caps = data[1] || {};
		var comps = componentsOf(caps);
		var sid = ensureSection('global_app');
		var m = new form.Map(APP);
		var s = m.section(form.NamedSection, sid, 'global_app', _('App Update'));

		var o = s.option(form.ListValue, 'gh_proxy_url', _('GitHub Proxy'), _('Use GitHub instead of proxy nodes for component updates.'));
		o.default = '';
		o.value('', _('Close(Not use)'));
		o.value('https://gh-proxy.org/', 'gh-proxy.org');
		o.value('https://ghproxy.cc/', 'ghproxy.cc');
		o.value('https://mirror.ghproxy.com/', 'ghproxy.com');
		o.value('https://ghfast.top/', 'ghfast.top');

		comps.forEach(function(comp) {
			if (comp.key === 'chinadns-ng')
				return;
			var name = comp.key.replace(/-/g, '_') + '_file';
			var opt = s.option(form.Value, name, _('%s App Path').replace('%s', comp.name));
			opt.default = comp.default_path || ('/usr/bin/' + comp.key);
			opt.placeholder = opt.default;
			opt.remove = function(section_id) {
				return uci.set(APP, section_id, name, this.default);
			};
		});

		o = s.option(form.DummyValue, 'tips', '　');
		o.cfgvalue = function() {
			return '<font color="red">' + _('if you want to run from memory, change the path, /tmp beginning then save the application and update it manually.') + '</font>';
		};
		o.rawhtml = true;
		o.renderWidget = function(section_id, option_index, cfgvalue) {
			var el = E('div');
			el.innerHTML = cfgvalue || '';
			return el;
		};

		var view = this;
		return m.render().then(function(node) {
			view.map = m;
			paintHtml(node);
			var section = node.querySelector('.cbi-section');
			var block = versionBlock(data[2], comps);
			if (section) {
				var title = section.querySelector('h3');
				if (title && title.nextSibling)
					section.insertBefore(block, title.nextSibling);
				else
					section.appendChild(block);
			}
			else {
				node.insertBefore(block, node.firstChild);
			}
			return node;
		});
	}
});
