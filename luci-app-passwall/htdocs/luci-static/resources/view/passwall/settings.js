'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require poll';
'require fs';
'require view.passwall.tools as pw';
'require view.passwall.runtime as runtime';

var TMP = '/tmp/etc/passwall';
var LOG_GLOBAL = TMP + '/acl/default/global.log';
var LOG_CHINA = TMP + '/acl/default/chinadns_ng.log';
var LOG_SMART = TMP + '/acl/default/smartdns.log';
var CACHE_VAR = TMP + '/var';

function present(v) {
	return !(v == null || v === false || v === '' || v === 0);
}

function tf(fmt, arg) {
	return _(fmt).replace('%s', arg);
}

function nodeIdOf(n) {
	if (!n)
		return '';
	return n.id || n['.name'] || '';
}

function groupName(v) {
	return (v && v.group && v.group !== '') ? v.group : _('default');
}

function isIPv4(v) {
	var m = String(v || '').match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
	if (!m)
		return false;
	for (var i = 1; i <= 4; i++) {
		var n = +m[i];
		if (m[i] !== String(n) || n > 255)
			return false;
	}
	return true;
}

function isIPv6(v) {
	v = String(v || '');
	if (v.indexOf(':') < 0)
		return false;
	return /^[0-9A-Fa-f:]+$/.test(v);
}

function isIpMask4(v) {
	var p = String(v || '').split('/');
	if (!isIPv4(p[0]))
		return false;
	if (p.length === 1)
		return true;
	if (p.length !== 2)
		return false;
	var n = +p[1];
	return p[1] !== '' && String(n) === p[1] && n >= 0 && n <= 32;
}

function isIpMask6(v) {
	var p = String(v || '').split('/');
	if (!isIPv6(p[0]))
		return false;
	if (p.length === 1)
		return true;
	if (p.length !== 2)
		return false;
	var n = +p[1];
	return p[1] !== '' && String(n) === p[1] && n >= 0 && n <= 128;
}

function isIpAddrPort(v) {
	var s = String(v || '');
	var idx = s.lastIndexOf(':');
	if (idx <= 0)
		return false;
	var host = s.substring(0, idx);
	var port = s.substring(idx + 1);
	if (!/^\d+$/.test(port))
		return false;
	var p = +port;
	if (p < 0 || p > 65535)
		return false;
	if (host.charAt(0) === '[' && host.charAt(host.length - 1) === ']')
		host = host.substring(1, host.length - 1);
	return isIPv4(host) || isIPv6(host);
}

function parseCache(text) {
	var fn = runtime.parseCache || (runtime.prototype && runtime.prototype.parseCache);
	return fn ? fn(text) : {};
}

function asText(v) {
	if (typeof v === 'string')
		return v;
	if (v == null)
		return '';
	try {
		return JSON.stringify(v, null, 2);
	}
	catch (e) {
		return String(v);
	}
}

function openLog(getter) {
	return getter.then(function(text) {
		var body = asText(text);
		var w = window.open('', '_blank');
		if (!w) {
			ui.showModal(_('Log'), [
				E('pre', { 'style': 'white-space:pre-wrap;max-height:70vh;overflow:auto' }, body),
				E('div', { 'class': 'right' }, [
					E('button', { 'class': 'btn', 'click': ui.hideModal }, _('CLOSE WIN'))
				])
			]);
			return;
		}
		var pre = w.document.createElement('pre');
		pre.style.whiteSpace = 'pre-wrap';
		pre.textContent = body;
		w.document.body.appendChild(pre);
	});
}

function ul(lines) {
	return E('ul', {}, lines.map(function(line) {
		return E('li', {}, line);
	}));
}

function baseDnsLines() {
	return [
		_('When not matching any domain name list:'),
		_('Remote DNS: Can avoid more DNS leaks, but some domestic domain names maybe to proxy!'),
		_('Direct DNS: Internet experience may be better, but DNS will be leaked!')
	];
}

function smartDnsLines() {
	return baseDnsLines().concat([
		_('Smart: Forward to both direct and remote DNS, if the direct DNS resolution result is a mainland China IP, then use the direct result, otherwise use the remote result.'),
		_('In smart mode, no-ip reply from Direct DNS:'),
		_('Do not accept: Wait and use Remote DNS Reply.'),
		_('Accept: Trust the Reply, using this option can improve DNS resolution speeds for some mainland IPv4-only sites.')
	]);
}

function svgIcon(d) {
	var ns = 'http://www.w3.org/2000/svg';
	var svg = document.createElementNS(ns, 'svg');
	svg.setAttribute('viewBox', '0 0 24 24');
	svg.setAttribute('width', '22');
	svg.setAttribute('height', '22');
	svg.setAttribute('fill', 'none');
	svg.setAttribute('stroke', 'currentColor');
	svg.setAttribute('stroke-width', '1.8');
	svg.setAttribute('stroke-linecap', 'round');
	svg.setAttribute('stroke-linejoin', 'round');
	svg.setAttribute('aria-hidden', 'true');
	String(d).split('|').forEach(function(part) {
		var path = document.createElementNS(ns, 'path');
		path.setAttribute('d', part);
		svg.appendChild(path);
	});
	return svg;
}

function statusCard(glyph, id, title, initial, extra) {
	var spanAttrs = { 'class': 'pw-state red' };
	if (extra && extra.spanId)
		spanAttrs.id = extra.spanId;
	var attrs = { 'class': 'pw-status-card' };
	if (extra && extra.check) {
		attrs.class = 'pw-status-card is-check';
		attrs.title = _('HTTP request latency, for reference only');
		attrs.click = extra.check;
	}
	return E('div', attrs, [
		E('div', { 'class': 'pw-status-icon' }, [ svgIcon(glyph) ]),
		E('h4', { 'id': id }, [
			E('span', { 'class': 'pw-status-title' }, title),
			E('span', spanAttrs, initial)
		])
	]);
}

function renderStatus() {
	return E('fieldset', { 'id': '_passwall_status_fieldset', 'class': 'cbi-section' }, [
		E('legend', {}, _('Running Status')),
		E('div', { 'class': 'pw-board' }, [
			statusCard('M4 7h16|M4 12h16|M4 17h10', 'status_tcp', 'TCP', _('NOT RUNNING')),
			statusCard('M12 3v4|M12 17v4|M5 8l7-3 7 3|M5 16l7 3 7-3|M8 12h8', 'status_udp', 'UDP', _('NOT RUNNING')),
			statusCard('M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z|M3 12h18|M12 3c2.4 2.6 3.6 5.8 3.6 9s-1.2 6.4-3.6 9c-2.4-2.6-3.6-5.8-3.6-9s1.2-6.4 3.6-9z', 'status_dns', 'DNS', _('NOT RUNNING')),
			statusCard('M12 3v18|M6 7h12|M8 7l-3 5h6L8 7z|M16 7l-3 5h6L16 7z', 'status_haproxy', 'HAProxy', 'N/A'),
			statusCard('M7 18h10a4 4 0 0 0 .2-8 5.5 5.5 0 0 0-10.5-1.6A3.5 3.5 0 0 0 7 18z', 'status_aliyun', _('AliCloud Conn.'), _('Touch Check'), {
				spanId: '_aliyun_status',
				check: function() { checkConnect('aliyun', 'https://www.aliyun.com/favicon.ico'); }
			}),
			statusCard('M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z|M12 8v8|M8 12h8', 'status_google', _('Google Conn.'), _('Touch Check'), {
				spanId: '_google_status',
				check: function() { checkConnect('google', 'https://www.google.com/generate_204'); }
			}),
			statusCard('M9 19c-4 1.5-4-2.5-6-3|M15 21v-3.5a3.4 3.4 0 0 0-.9-2.6c3-.3 6.1-1.5 6.1-6.6a5.1 5.1 0 0 0-1.4-3.5 4.7 4.7 0 0 0-.1-3.5s-1.1-.3-3.5 1.3a12.1 12.1 0 0 0-6.4 0C6.4 1 5.3 1.3 5.3 1.3a4.7 4.7 0 0 0-.1 3.5A5.1 5.1 0 0 0 3.8 8.3c0 5.1 3.1 6.2 6.1 6.6a3.4 3.4 0 0 0-.9 2.6V21', 'status_github', _('GitHub Conn.'), _('Touch Check'), {
				spanId: '_github_status',
				check: function() { checkConnect('github', 'https://github.com/favicon.ico'); }
			}),
			statusCard('M4 8h16a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-6a2 2 0 0 1 2-2z|M10 10.5v5l5-2.5-5-2.5z', 'status_youtube', _('YouTube Conn.'), _('Touch Check'), {
				spanId: '_youtube_status',
				check: function() { checkConnect('youtube', 'https://www.youtube.com/generate_204'); }
			})
		]),
		E('div', { 'id': 'status_now_node', 'class': 'pw-now', 'hidden': 'hidden' })
	]);
}

function fillStatus(el, label, klass, text) {
	while (el.firstChild)
		el.removeChild(el.firstChild);
	el.appendChild(E('span', { 'class': 'pw-status-title' }, label));
	el.appendChild(E('span', { 'class': 'pw-state ' + klass }, text));
}

function setRun(id, label, on) {
	var el = document.getElementById(id);
	if (!el)
		return;
	fillStatus(el, label, on ? 'green' : 'red', on ? _('RUNNING') : _('NOT RUNNING'));
}

function paintIndex(data) {
	data = data || {};
	setRun('status_tcp', 'TCP', !!data.tcp_status);
	setRun('status_udp', 'UDP', !!data.udp_status);
	setRun('status_dns', 'DNS', !!data.dns_mode_status);
	var hp = document.getElementById('status_haproxy');
	if (!hp)
		return;
	var klass = 'red';
	var text = _('NOT RUNNING');
	if (data.haproxy_status === '-1')
		text = _('UNINSTALLED');
	else if (data.haproxy_status === '0') {
		klass = 'green';
		text = _('RUNNING');
	}
	fillStatus(hp, 'HAProxy', klass, text);
}

function checkConnect(type, url) {
	var s = document.getElementById('_' + type + '_status');
	if (!s)
		return;
	var card = s.closest ? s.closest('.pw-status-card') : null;
	if (card) {
		card.onclick = null;
		card.title = _('HTTP request latency, for reference only');
	}
	s.className = 'pw-state';
	s.textContent = _('Check...');
	pw.get('connect_status', { url: url }).then(function(rv) {
		rv = rv || {};
		if (rv.ping_type && rv.ping_type === 'curl') {
			var use = parseFloat(rv.use_time);
			if (use < 1000)
				s.className = 'pw-state green';
			else if (use < 2000)
				s.className = 'pw-state yellow';
			else
				s.className = 'pw-state red';
			s.textContent = rv.use_time + ' ms';
			if (card)
				card.title += '\n' + _('Initial handshake time') + ': ' + rv.handshake_time + ' ms';
		}
		else if (rv.status) {
			s.className = 'pw-state green';
			s.textContent = _('Working...');
		}
		else {
			s.className = 'pw-state red';
			s.textContent = _('Problem detected!');
		}
		if (card)
			card.onclick = function() { checkConnect(type, url); };
	}).catch(function() {
		s.className = 'pw-state red';
		s.textContent = _('Problem detected!');
		if (card)
			card.onclick = function() { checkConnect(type, url); };
	});
}

function remarkNode(holder, remark) {
	while (holder.firstChild)
		holder.removeChild(holder.firstChild);
	var text = String(remark || '');
	if (!text)
		return;
	var parts = text.split('：[');
	if (parts.length === 1) {
		holder.textContent = text;
		return;
	}
	holder.appendChild(document.createTextNode(parts[0] + '：'));
	for (var i = 1; i < parts.length; i++) {
		holder.appendChild(E('br'));
		holder.appendChild(document.createTextNode('[' + parts[i]));
	}
}

function paintNowNode(data, remarks) {
	var el = document.getElementById('status_now_node');
	if (!el)
		return;
	var id = data && data.global;
	var remark = id ? (remarks[id] || id) : '';
	while (el.firstChild)
		el.removeChild(el.firstChild);
	if (!remark) {
		el.hidden = true;
		return;
	}
	el.hidden = false;
	el.appendChild(document.createTextNode(_('Current Node') + ': '));
	var span = E('span');
	remarkNode(span, remark);
	el.appendChild(span);
}

function paintSocksRuntime(cache, remarks) {
	document.querySelectorAll('[id^="pw-now-"]').forEach(function(holder) {
		var id = holder.getAttribute('data-socks-id');
		var nid = cache[id];
		remarkNode(holder, nid ? (remarks[nid] || nid) : '');
	});
}

function paintSocksPorts() {
	var rows = document.querySelectorAll('._socks_status');
	var jobs = [];
	for (var i = 0; i < rows.length; i++) {
		(function(el, index) {
			var id = el.getAttribute('socks_id');
			if (!id)
				return;
			jobs.push(pw.get('socks_status', { index: String(index), id: id }).then(function(result) {
				result = result || {};
				var socks = el.querySelector('._socks');
				var http = el.querySelector('._http');
				if (socks) {
					socks.textContent = result.socks_status ? '✓' : 'X';
					socks.style.fontWeight = 'bold';
					socks.style.color = result.socks_status ? 'green' : 'red';
				}
				if (http) {
					if (result.use_http) {
						http.textContent = result.http_status ? '✓' : 'X';
						http.style.fontWeight = 'bold';
						http.style.color = result.http_status ? 'green' : 'red';
					}
					else {
						http.textContent = '';
					}
				}
			}));
		})(rows[i], i);
	}
	return Promise.all(jobs);
}

function buildSelect(id, items, current) {
	var sel = E('select', { 'id': id, 'class': 'cbi-input-select', 'style': 'min-width:220px' });
	var groups = {};
	var order = [];
	var seen = {};
	items.forEach(function(it) {
		seen[it.value] = true;
		if (!it.group) {
			sel.appendChild(E('option', { 'value': it.value }, it.label));
			return;
		}
		if (!groups[it.group]) {
			groups[it.group] = [];
			order.push(it.group);
		}
		groups[it.group].push(it);
	});
	order.forEach(function(g) {
		var og = E('optgroup', { 'label': g });
		groups[g].forEach(function(it) {
			og.appendChild(E('option', { 'value': it.value }, it.label));
		});
		sel.appendChild(og);
	});
	if (current != null && current !== '' && !seen[current])
		sel.appendChild(E('option', { 'value': current }, current));
	if (current != null)
		sel.value = current;
	return sel;
}

function groupedNode(option, items, track) {
	items.forEach(function(it) {
		option.value(it.value, it.label);
	});
	option.formvalue = function(section_id) {
		var sel = document.getElementById(this.cbid(section_id));
		if (sel)
			return sel.value;
		var v = uci.get('passwall', section_id, this.option);
		return v == null ? '' : v;
	};
	option.write = function(section_id, value) {
		if (value == null || value === '') {
			if (this.rmempty !== false)
				return uci.unset('passwall', section_id, this.option);
		}
		return uci.set('passwall', section_id, this.option, value);
	};
	option.remove = function(section_id) {
		return uci.unset('passwall', section_id, this.option);
	};
	option.renderWidget = function(section_id, option_index, cfgvalue) {
		var self = this;
		var sel = buildSelect(this.cbid(section_id), items, cfgvalue == null ? '' : cfgvalue);
		sel.addEventListener('change', function(ev) {
			if (track && track.flag)
				track.flag(section_id, sel.value);
			if (typeof self.onchange === 'function')
				self.onchange(ev, section_id, sel.value);
		});
		return sel;
	};
	return option;
}

function setFlag(opt, section, on) {
	if (!opt)
		return;
	var el = opt.getUIElement(section);
	if (el && typeof el.setValue === 'function')
		el.setValue(!!on);
	else
		uci.set('passwall', section, opt.option, on ? '1' : '0');
}

function setList(opt, section, value) {
	if (!opt)
		return;
	var el = opt.getUIElement(section);
	if (el && typeof el.setValue === 'function')
		el.setValue(value);
	else
		uci.set('passwall', section, opt.option, value);
}

function logFileOption(option, path, exists, opener) {
	option.renderWidget = function() {
		var kids = [ E('code', {}, path), '\u00a0\u00a0' ];
		if (exists) {
			kids.push(E('input', {
				'class': 'btn cbi-button cbi-button-apply',
				'type': 'button',
				'value': _('View Log'),
				'click': function(ev) {
					ev.preventDefault();
					opener();
				}
			}));
		}
		return E('span', {}, kids);
	};
}

function getBg(el) {
	if (!el)
		return null;
	var style = window.getComputedStyle(el);
	var bgImage = style.backgroundImage;
	var bgColor = style.backgroundColor;
	if (bgImage !== 'none' || (!/rgba\([^,]+,[^,]+,[^,]+,\s*0\)/.test(bgColor) && bgColor !== 'transparent'))
		return style.background;
	return null;
}

function renderBackup() {
	var modal;
	var fileInput;
	var uploadBtn;

	function showUpload() {
		modal.style.background = getBg(document.querySelector('.cbi-section')) || getBg(document.body) || '';
		modal.style.display = 'block';
		fileInput.focus();
	}

	function closeUpload() {
		fileInput.value = '';
		modal.style.display = 'none';
	}

	function dlBackup() {
		return pw.call('create_backup').then(function(res) {
			if (!res || res.code === 0 || !res.filename || !res.output)
				throw new Error('备份失败！');
			var binary = atob(res.output);
			var bytes = new Uint8Array(binary.length);
			for (var i = 0; i < binary.length; i++)
				bytes[i] = binary.charCodeAt(i);
			var blob = new Blob([bytes], { 'type': 'application/gzip' });
			var url = window.URL.createObjectURL(blob);
			var a = E('a', { 'href': url, 'download': res.filename });
			document.body.appendChild(a);
			a.click();
			a.remove();
			window.URL.revokeObjectURL(url);
		}).catch(function(err) {
			alert(err.message || String(err));
		});
	}

	function doReset(type) {
		if (type !== 'client' && type !== 'server')
			return;
		var name = (type === 'client' ? _('Client') : _('Server')).toLowerCase();
		var message = tf('Do you want to restore the %s to default settings?', name);
		var confirmMessage = tf('Are you sure you want to restore the %s to default settings?', name);
		var redirect = type === 'client' ? pw.pageUrl('log') : pw.pageUrl('server');
		if (confirm(message)) {
			window.setTimeout(function() {
				if (confirm(confirmMessage)) {
					pw.call('reset_config', { type: type }).then(function() {
						window.location.href = redirect;
					});
				}
			}, 1000);
		}
	}

	function doUpload() {
		var client = modal.querySelector('input[name="client"]').checked;
		var server = modal.querySelector('input[name="server"]').checked;
		if (!client && !server)
			return;
		var type = (client === server) ? 'all' : (client ? 'client' : 'server');
		var file = fileInput.files && fileInput.files[0];
		if (!file) {
			alert(_('Please select a file first.'));
			return;
		}
		if (!file.name.endsWith('.tar.gz')) {
			alert(_('Invalid file type. Please upload a .tar.gz file.'));
			fileInput.value = '';
			return;
		}
		if (file.size > 10 * 1024 * 1024) {
			alert(_('File size exceeds 10MB limit.'));
			fileInput.value = '';
			return;
		}
		var reader = new FileReader();
		reader.onload = function(e) {
			var binary = new Uint8Array(e.target.result);
			var binaryText = '';
			var step = 4096;
			for (var i = 0; i < binary.length; i += step)
				binaryText += String.fromCharCode.apply(null, binary.subarray(i, i + step));
			var base64Data = btoa(binaryText);
			var targetByteSize = 64 * 1024;
			var chunkSize = Math.floor(targetByteSize * 4 / 3);
			chunkSize = chunkSize + (4 - (chunkSize % 4)) % 4;
			var totalChunks = Math.ceil(base64Data.length / chunkSize);
			var currentChunk = 0;
			var label = _('UL Restore');

			function sendNextChunk() {
				if (currentChunk >= totalChunks) {
					uploadBtn.value = label;
					window.location.href = (type === 'server') ? pw.pageUrl('server') : pw.pageUrl('log');
					return;
				}
				var chunk = base64Data.substring(currentChunk * chunkSize, (currentChunk + 1) * chunkSize);
				pw.call('restore_backup', {
					type: type,
					filename: file.name,
					chunk: chunk,
					chunk_index: String(currentChunk),
					total_chunks: String(totalChunks)
				}).then(function(resp) {
					resp = resp || {};
					if (resp.status === 'success') {
						currentChunk++;
						uploadBtn.value = 'Uploading... ' + Math.floor((currentChunk / totalChunks) * 100) + '%';
						sendNextChunk();
					}
					else {
						alert('Upload error: ' + (resp.message || ''));
						uploadBtn.value = label;
					}
				}).catch(function(err) {
					alert('Upload failed with status ' + (err && err.message ? err.message : err));
					uploadBtn.value = label;
				});
			}
			sendNextChunk();
		};
		reader.readAsArrayBuffer(file);
	}

	fileInput = E('input', { 'class': 'cbi-input-file', 'type': 'file', 'id': 'ulfile', 'accept': '.tar.gz' });
	uploadBtn = E('input', {
		'class': 'btn cbi-button cbi-button-apply',
		'type': 'button',
		'id': 'upload-btn',
		'value': _('UL Restore'),
		'click': doUpload
	});
	modal = E('div', { 'id': 'upload-modal', 'class': 'up-modal', 'style': 'display:none' }, [
		E('div', { 'class': 'up-modal-content' }, [
			E('h3', {}, _('Restore Backup File')),
			E('div', { 'class': 'up-cbi-value-field' }, [ fileInput ]),
			E('div', { 'class': 'up-cbi-checkbox' }, [
				E('label', {}, [
					E('input', { 'class': 'cbi-input-checkbox', 'type': 'checkbox', 'name': 'client', 'value': '1', 'checked': 'checked' }),
					_('Client')
				]),
				E('label', {}, [
					E('input', { 'class': 'cbi-input-checkbox', 'type': 'checkbox', 'name': 'server', 'value': '1' }),
					_('Server')
				])
			]),
			E('div', { 'class': 'up-button-container' }, [
				uploadBtn,
				E('input', {
					'class': 'btn cbi-button cbi-button-remove',
					'type': 'button',
					'value': _('CLOSE WIN'),
					'click': closeUpload
				})
			])
		])
	]);

	return E('div', {}, [
		E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Backup and Restore')),
			E('div', { 'class': 'cbi-section-descr' }, [
				_('Backup or Restore Client and Server Configurations.'),
				E('br'),
				E('font', { 'color': 'red' }, _('Note: Restoring configurations across different versions may cause compatibility issues.'))
			])
		]),
		E('div', { 'class': 'cbi-value', 'id': '_backup_div' }, [
			E('label', { 'class': 'cbi-value-title' }, _('Create Backup File')),
			E('div', { 'class': 'cbi-value-field' }, [
				E('input', {
					'class': 'btn cbi-button cbi-button-save',
					'type': 'button',
					'value': _('DL Backup'),
					'click': dlBackup
				})
			])
		]),
		E('div', { 'class': 'cbi-value', 'id': '_upload_div' }, [
			E('label', { 'class': 'cbi-value-title' }, _('Restore Backup File')),
			E('div', { 'class': 'cbi-value-field' }, [
				E('input', {
					'class': 'btn cbi-button cbi-button-apply',
					'type': 'button',
					'value': _('RST Backup'),
					'click': showUpload
				})
			])
		]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, tf('Reset %s Configuration', _('Client'))),
			E('div', { 'class': 'cbi-value-field' }, [
				E('input', {
					'class': 'btn cbi-button cbi-button-reset',
					'type': 'button',
					'value': _('Do Reset'),
					'click': function() { doReset('client'); }
				})
			])
		]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, tf('Reset %s Configuration', _('Server'))),
			E('div', { 'class': 'cbi-value-field' }, [
				E('input', {
					'class': 'btn cbi-button cbi-button-reset',
					'type': 'button',
					'value': _('Do Reset'),
					'click': function() { doReset('server'); }
				})
			])
		]),
		modal
	]);
}

function renderFaq() {
	var hideUrl = window.location.origin + pw.pageUrl('hide');
	var showUrl = window.location.origin + pw.pageUrl('show');

	function hideMenu(ev) {
		if (ev)
			ev.preventDefault();
		if (confirm(_('Are you sure to hide?')) === true) {
			pw.call('hide_menu').then(function() {
				window.location.reload();
			});
		}
	}

	function showMenu(ev) {
		if (ev)
			ev.preventDefault();
		pw.call('show_menu').then(function() {
			window.location.reload();
		});
	}

	return E('div', { 'class': 'dns-con' }, [
		E('div', { 'id': 'faq_dns' }, [
			E('ul', {}, [
				E('b', { 'class': 'faq-title' }, _('DNS related issues:')),
				E('li', { 'class': 'dns-item' }, [
					'1. ',
					E('span', {}, _('Certain browsers such as Chrome have built-in DNS service, which may affect DNS resolution settings. You can go to \'Settings -> Privacy and security -> Use secure DNS\' menu to turn it off.'))
				]),
				E('li', { 'class': 'dns-item' }, [
					'2. ',
					E('span', {}, _('If you are unable to access the internet after reboot, please try clearing the cache of your terminal devices (make sure to close all open browser application windows first, this step is especially important):')),
					E('ul', {}, [
						E('li', { 'class': 'dns-list' }, [ ' ◦ ', E('span', {}, _('For Windows systems, open Command Prompt and run the command \'ipconfig /flushdns\'.')) ]),
						E('li', { 'class': 'dns-list' }, [ ' ◦ ', E('span', {}, _('For Mac systems, open Terminal and run the command \'sudo killall -HUP mDNSResponder\'.')) ]),
						E('li', { 'class': 'dns-list' }, [ ' ◦ ', E('span', {}, _('For mobile devices, you can clear it by reconnecting to the network, such as toggling Airplane Mode and reconnecting to WiFi.')) ])
					])
				]),
				E('li', { 'class': 'dns-item' }, [
					'3. ',
					E('span', {}, _('Please make sure your device\'s network settings point both the DNS server and default gateway to this router, to ensure DNS queries are properly routed.'))
				])
			])
		]),
		E('div', { 'id': 'faq_reset' }, [
			E('a', { 'href': '#', 'class': 'reset-title', 'click': hideMenu }, _(' Hide in main menu:')),
			E('br'),
			_(' Browser access: '),
			E('a', { 'href': '#', 'click': hideMenu }, hideUrl),
			E('br'),
			E('a', { 'href': '#', 'class': 'reset-title', 'click': showMenu }, _(' Show in main menu:')),
			E('br'),
			_(' Browser access: '),
			E('a', { 'href': '#', 'click': showMenu }, showUrl),
			E('br')
		])
	]);
}

function renderProxySwitch(section, flags) {
	function gfw() {
		setFlag(flags.use_gfw_list, section, true);
		setList(flags.chn_list, section, '0');
		setList(flags.tcp_proxy_mode, section, 'disable');
		setList(flags.udp_proxy_mode, section, 'disable');
	}
	function chn() {
		setFlag(flags.use_gfw_list, section, true);
		setList(flags.chn_list, section, 'direct');
		setList(flags.tcp_proxy_mode, section, 'proxy');
		setList(flags.udp_proxy_mode, section, 'proxy');
	}
	function home() {
		setFlag(flags.use_gfw_list, section, false);
		setList(flags.chn_list, section, 'proxy');
		setList(flags.tcp_proxy_mode, section, 'disable');
		setList(flags.udp_proxy_mode, section, 'disable');
	}
	function globalMode() {
		setFlag(flags.use_gfw_list, section, false);
		setList(flags.chn_list, section, '0');
		setList(flags.tcp_proxy_mode, section, 'proxy');
		setList(flags.udp_proxy_mode, section, 'proxy');
	}
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, _('Switch Mode')),
		E('div', { 'class': 'cbi-value-field' }, [
			E('div', {}, [
				E('input', { 'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'value': _('GFW List'), 'click': gfw }),
				' ',
				E('input', { 'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'value': _('Not China List'), 'click': chn }),
				' ',
				E('input', { 'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'value': _('China List'), 'click': home }),
				' ',
				E('input', { 'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'value': _('Global Proxy'), 'click': globalMode })
			])
		])
	]);
}

function missingProxyWidget() {
	return E('div', {}, [
		E('div', { 'class': 'cbi-checkbox' }, [
			E('input', { 'class': 'cbi-input-checkbox', 'type': 'checkbox', 'disabled': 'disabled' })
		]),
		E('div', { 'class': 'cbi-value-description' }, [
			E('font', { 'color': 'red' }, _('Missing components, transparent proxy is unavailable.'))
		])
	]);
}

function fileExists(path) {
	return fs.stat(path).then(function() {
		return true;
	}).catch(function() {
		return false;
	});
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('passwall'),
			pw.loadCaps(),
			fileExists(LOG_GLOBAL),
			fileExists(LOG_CHINA),
			fileExists(LOG_SMART),
			fs.read(CACHE_VAR).catch(function() { return ''; })
		]);
	},

	render: function(data) {
		var caps = data[1] || {};
		var nodes = caps.nodes || [];
		var nodeList = caps.node_list || {};
		var logGlobal = !!data[2];
		var logChina = !!data[3];
		var logSmart = !!data[4];
		var cacheText = data[5] || '';
		var globals = uci.sections('passwall', 'global') || [];
		var sid = globals.length ? globals[0]['.name'] : pw.sectionId('passwall', 'global');
		var remarks = {};
		nodes.forEach(function(n) {
			remarks[nodeIdOf(n)] = n.remark || '';
		});

		var rootKids = [ renderStatus() ];
		if (!sid) {
			rootKids.push(E('div', { 'class': 'alert-message warning' }, _('Global') ));
			return E('div', {}, rootKids);
		}

		var loadedNode = uci.get('passwall', sid, 'node') || '';
		var nodeById = function(id) {
			for (var i = 0; i < nodes.length; i++)
				if (nodeIdOf(nodes[i]) === id)
					return nodes[i];
			return null;
		};
		var loadedObj = nodeById(loadedNode);
		var nodeSaveBefore = loadedObj ? nodeIdOf(loadedObj) : '';
		var hasCore = present(caps.singbox) || present(caps.xray);
		var normalCount = (nodeList.normal_list || []).length;
		var ifaceCount = (nodeList.iface_list || []).length;
		var hasNodes = nodes.length > 0;
		var hasNormal = normalCount > 0 || ifaceCount > 0;
		var showShunt = hasCore && hasNodes && hasNormal && loadedObj && loadedObj.protocol === '_shunt';
		var showNoNodeTip = hasCore && hasNodes && !hasNormal;
		var shuntIds = {};
		var mods = caps.lsmod || '';
		var transparent = (mods.indexOf('REDIRECT') >= 0 && mods.indexOf('TPROXY') >= 0) ||
			(mods.indexOf('nft_redir') >= 0 && mods.indexOf('nft_tproxy') >= 0);

		var m = new form.Map('passwall', '', '');
		var s = m.section(form.NamedSection, sid, 'global');
		s.tab('Main', _('Main'));
		if (showShunt)
			s.tab('Shunt', _('Shunt Rule'));
		s.tab('DNS', _('DNS'));
		s.tab('Proxy', _('Mode'));
		s.tab('log', _('Log'));
		s.tab('faq', 'FAQ');
		s.tab('maintain', _('Maintain'));
		s.tab('socks', _('Socks Config'));

		var o;
		o = s.taboption('Main', form.Flag, 'enabled', _('Main switch'));
		o.rmempty = false;

		var nodeOpt = s.taboption('Main', form.ListValue, 'node', E('a', { 'class': 'pw-warn' }, _('Proxy Node')));
		var shuntSel = s.taboption('Main', form.Value, '_node_sel_shunt', '');
		shuntSel.depends({ node: '__always__' });
		shuntSel.write = function() {};
		shuntSel.remove = function() {};
		shuntSel.formvalue = function(section_id) {
			var input = document.getElementById(this.cbid(section_id));
			if (input)
				return input.value;
			return shuntIds[uci.get('passwall', section_id, 'node')] ? '1' : '';
		};
		shuntSel.render = function(section_id) {
			var value = shuntIds[uci.get('passwall', section_id, 'node')] ? '1' : '';
			return E('div', { 'class': 'pw-hidden-field', 'id': 'cbi-passwall-' + section_id + '-_node_sel_shunt' }, [
				E('input', { 'type': 'hidden', 'id': this.cbid(section_id), 'value': value })
			]);
		};

		function setShuntFlag(section_id, nodeValue) {
			var input = document.getElementById(shuntSel.cbid(section_id));
			if (input)
				input.value = shuntIds[nodeValue] ? '1' : '';
			var tab = document.getElementById('tab.passwall.' + sid + '.Shunt');
			var on = !!shuntIds[nodeValue] && nodeValue === (loadedObj ? nodeIdOf(loadedObj) : '');
			if (tab && tab.parentNode && tab.parentNode.tagName === 'LI')
				tab.parentNode.style.display = on ? '' : 'none';
		}

		if (showNoNodeTip) {
			o = s.taboption('Main', form.DummyValue, 'tips', '　');
			o.depends({ node: '', '!reverse': true });
			o.renderWidget = function() {
				return E('a', { 'class': 'pw-warn' }, _('There are no available nodes, please add or subscribe nodes first.'));
			};
		}

		o = s.taboption('Main', form.Value, 'node_socks_port', _('Node') + ' Socks ' + _('Listen Port'));
		o.default = '1070';
		o.placeholder = '1070';
		o.datatype = 'range(1,65535)';
		o.depends({ node: '', '!reverse': true });

		o = s.taboption('Main', form.Flag, 'node_socks_bind_local', _('Node') + ' Socks ' + _('Bind Local'), _('When selected, it can only be accessed localhost.'));
		o.default = '1';
		o.depends({ node: '', '!reverse': true });

		var nodeBefore = s.taboption('Main', form.DummyValue, 'node_save_before', '');
		nodeBefore.render = function() {
			return E('div', { 'class': 'pw-hidden-field' }, [
				E('input', { 'type': 'hidden', 'name': 'node_save_before', 'id': 'node_save_before', 'value': nodeSaveBefore })
			]);
		};

		var dnsShunt = s.taboption('DNS', form.ListValue, 'dns_shunt', 'DNS ' + _('Shunt'));
		dnsShunt.value('dnsmasq', 'Dnsmasq');
		dnsShunt.value('chinadns-ng', _('ChinaDNS-NG (recommended)'));
		if (present(caps.smartdns))
			dnsShunt.value('smartdns', 'SmartDNS');
		dnsShunt.write = function(section, value) {
			var old = uci.get('passwall', section, 'dns_shunt');
			if (old && old !== value)
				uci.set('passwall', section, 'flush_set', '1');
			return form.ListValue.prototype.write.apply(this, arguments);
		};

		var directMode = s.taboption('DNS', form.ListValue, 'direct_dns_mode', _('Direct DNS') + ' ' + _('Request protocol'));
		directMode.value('', _('Auto'));
		directMode.value('udp', tf('Requery DNS By %s', 'UDP'));
		directMode.value('tcp', tf('Requery DNS By %s', 'TCP'));
		directMode.depends({ dns_shunt: 'dnsmasq' });
		directMode.depends({ dns_shunt: 'chinadns-ng' });

		o = s.taboption('DNS', form.Value, 'direct_dns', _('Direct DNS'));
		o.datatype = 'or(ipaddr,ipaddrport(1))';
		o.default = '223.5.5.5';
		['223.5.5.5', '223.6.6.6', '180.184.1.1', '180.184.2.2', '114.114.114.114', '114.114.115.115', '119.28.28.28'].forEach(function(v) {
			o.value(v);
		});
		o.depends({ dns_shunt: 'dnsmasq', direct_dns_mode: 'udp' });
		o.depends({ dns_shunt: 'dnsmasq', direct_dns_mode: 'tcp' });
		o.depends({ dns_shunt: 'chinadns-ng', direct_dns_mode: 'udp' });
		o.depends({ dns_shunt: 'chinadns-ng', direct_dns_mode: 'tcp' });

		if (present(caps.smartdns)) {
			o = s.taboption('DNS', form.DynamicList, 'smartdns_direct_dns', _('Direct DNS'));
			o.placeholder = _('Auto');
			o.rmempty = true;
			['223.5.5.5', '119.29.29.29', 'tcp://223.5.5.5', 'tcp://114.114.114.114', 'tls://dot.pub,1.12.12.12', 'tls://dns.alidns.com,223.5.5.5', 'https://223.5.5.5/dns-query', 'https://1.12.12.12/dns-query'].forEach(function(v) {
				o.value(v);
			});
			o.depends({ dns_shunt: 'smartdns' });
		}

		o = s.taboption('DNS', form.Flag, 'filter_proxy_ipv6', _('Filter Proxy Host IPv6'));
		o.default = '0';

		var dnsMode = s.taboption('DNS', form.ListValue, 'dns_mode', _('Filter Mode'));
		dnsMode.default = 'tcp';
		dnsMode.value('udp', tf('Requery DNS By %s', 'UDP'));
		dnsMode.value('tcp', tf('Requery DNS By %s', 'TCP'));
		if (present(caps.dns2socks))
			dnsMode.value('dns2socks', 'dns2socks');
		if (present(caps.singbox))
			dnsMode.value('sing-box', 'Sing-Box');
		if (present(caps.xray))
			dnsMode.value('xray', 'Xray');
		dnsMode.depends({ dns_shunt: 'chinadns-ng', _node_sel_shunt: '' });
		dnsMode.depends({ dns_shunt: 'dnsmasq', _node_sel_shunt: '' });

		var smartdnsMode = null;
		if (present(caps.smartdns)) {
			smartdnsMode = s.taboption('DNS', form.ListValue, 'smartdns_dns_mode', _('Filter Mode'));
			smartdnsMode.value('socks', 'Socks');
			if (present(caps.singbox))
				smartdnsMode.value('sing-box', 'Sing-Box');
			if (present(caps.xray))
				smartdnsMode.value('xray', 'Xray');
			smartdnsMode.depends({ dns_shunt: 'smartdns', _node_sel_shunt: '' });
			smartdnsMode.write = function(section, value) {
				if (value === 'socks')
					uci.unset('passwall', section, 'v2ray_dns_mode');
				return form.ListValue.prototype.write.apply(this, arguments);
			};
		}

		var xrayDns = s.taboption('DNS', form.ListValue, 'xray_dns_mode', _('Remote DNS') + ' ' + _('Request protocol'));
		xrayDns.default = 'tcp';
		xrayDns.value('tcp', 'TCP');
		xrayDns.value('udp', 'UDP');
		xrayDns.value('doh', 'DoH');
		xrayDns.depends('dns_mode', 'xray');
		xrayDns.depends('smartdns_dns_mode', 'xray');
		xrayDns.cfgvalue = function(section) {
			return uci.get('passwall', section, 'v2ray_dns_mode');
		};
		xrayDns.write = function(section, value) {
			var sm = smartdnsMode && smartdnsMode.formvalue(section);
			if (dnsMode.formvalue(section) === 'xray' || sm === 'xray')
				uci.set('passwall', section, 'v2ray_dns_mode', value);
		};

		var singDns = s.taboption('DNS', form.ListValue, 'singbox_dns_mode', _('Remote DNS') + ' ' + _('Request protocol'));
		singDns.default = 'tcp';
		singDns.value('tcp', 'TCP');
		singDns.value('udp', 'UDP');
		singDns.value('doh', 'DoH');
		singDns.value('http3', 'HTTP3(DoH3)');
		singDns.value('tls', 'TLS(DoT)');
		singDns.value('quic', 'QUIC(DoQ)');
		singDns.depends('dns_mode', 'sing-box');
		singDns.depends('smartdns_dns_mode', 'sing-box');
		singDns.cfgvalue = function(section) {
			return uci.get('passwall', section, 'v2ray_dns_mode');
		};
		singDns.write = function(section, value) {
			var sm = smartdnsMode && smartdnsMode.formvalue(section);
			if (dnsMode.formvalue(section) === 'sing-box' || sm === 'sing-box')
				uci.set('passwall', section, 'v2ray_dns_mode', value);
		};

		function dnsModeSave(section) {
			var idVal = nodeOpt.formvalue(section) || '';
			if (!idVal)
				return;
			var node = nodeById(idVal);
			if (!node || node.protocol !== '_shunt')
				return;
			var typeVal = node.type;
			if (typeVal !== 'Xray' && typeVal !== 'sing-box')
				return;
			var dnsShuntVal = dnsShunt.formvalue(section);
			var key = (dnsShuntVal !== 'smartdns') ? 'dns_mode' : 'smartdns_dns_mode';
			var currentVal = uci.get('passwall', section, key) || '';
			var newVal = (typeVal === 'Xray') ? 'xray' : 'sing-box';
			if (currentVal !== newVal) {
				uci.set('passwall', section, key, newVal);
				uci.unset('passwall', section, key === 'dns_mode' ? 'smartdns_dns_mode' : 'dns_mode');
			}
			var field = (typeVal === 'Xray') ? xrayDns : singDns;
			var v2 = field && field.formvalue(section);
			if (v2 && uci.get('passwall', section, 'v2ray_dns_mode') !== v2)
				uci.set('passwall', section, 'v2ray_dns_mode', v2);
		}

		dnsMode.write = function(section, value) {
			if (value !== 'sing-box' && value !== 'xray')
				uci.unset('passwall', section, 'v2ray_dns_mode');
			return form.ListValue.prototype.write.apply(this, arguments);
		};
		dnsMode.remove = function(section) {
			if (smartdnsMode && smartdnsMode.formvalue(section))
				return uci.unset('passwall', section, 'dns_mode');
			dnsModeSave(section);
		};
		if (smartdnsMode) {
			smartdnsMode.remove = function(section) {
				if (dnsMode.formvalue(section))
					return uci.unset('passwall', section, 'smartdns_dns_mode');
				dnsModeSave(section);
			};
			o = s.taboption('DNS', form.DynamicList, 'smartdns_remote_dns', _('Remote DNS'));
			['tcp://1.1.1.1', 'tcp://8.8.4.4', 'tcp://8.8.8.8', 'tcp://9.9.9.9', 'tcp://208.67.222.222', 'tls://1.1.1.1', 'tls://8.8.4.4', 'tls://8.8.8.8', 'tls://9.9.9.9', 'tls://208.67.222.222', 'https://1.1.1.1/dns-query', 'https://8.8.4.4/dns-query', 'https://8.8.8.8/dns-query', 'https://9.9.9.9/dns-query', 'https://208.67.222.222/dns-query', 'https://dns.adguard.com/dns-query,94.140.14.14', 'https://doh.libredns.gr/dns-query,116.202.176.26', 'https://doh.libredns.gr/ads,116.202.176.26'].forEach(function(v) {
				o.value(v);
			});
			o.depends({ dns_shunt: 'smartdns', smartdns_dns_mode: 'socks' });
			o.cfgvalue = function(section) {
				var v = uci.get('passwall', section, 'smartdns_remote_dns');
				if (v == null || v === '')
					return ['tcp://1.1.1.1'];
				return v;
			};
		}

		var socksPort = uci.get('passwall', sid, 'node_socks_port') || '1070';
		var socksTable = [{
			id: '127.0.0.1:' + socksPort,
			remark: '127.0.0.1:' + socksPort + ' - ' + _('Proxy Node')
		}];
		(uci.sections('passwall', 'socks') || []).forEach(function(sec) {
			if (String(sec.enabled) === '1' && sec.node) {
				var remark = null;
				nodes.forEach(function(n) {
					if (sec.node === nodeIdOf(n))
						remark = n.remark;
				});
				var id = '127.0.0.1:' + sec.port;
				socksTable.push({
					id: id,
					remark: id + ' - ' + (remark || _('Misconfigured'))
				});
			}
		});

		o = s.taboption('DNS', form.Value, 'socks_server', _('Socks Server'), _('Make sure socks service is available on this address.'));
		socksTable.forEach(function(v) {
			o.value(v.id, v.remark);
		});
		o.default = socksTable[0].id;
		o.datatype = 'ipaddrport';
		o.validate = function(section, value) {
			if (!isIpAddrPort(value))
				return _('Socks Server') + ' ' + _('Not valid IP format, please re-enter!');
			return true;
		};
		o.depends({ dns_mode: 'dns2socks' });

		o = s.taboption('DNS', form.Value, 'remote_dns', _('Remote DNS'));
		o.datatype = 'or(ipaddr,ipaddrport(1))';
		o.default = '1.1.1.1';
		o.value('1.1.1.1', '1.1.1.1 (CloudFlare)');
		o.value('1.1.1.2', '1.1.1.2 (CloudFlare-Security)');
		o.value('8.8.4.4', '8.8.4.4 (Google)');
		o.value('8.8.8.8', '8.8.8.8 (Google)');
		o.value('9.9.9.9', '9.9.9.9 (Quad9)');
		o.value('149.112.112.112', '149.112.112.112 (Quad9)');
		o.value('208.67.220.220', '208.67.220.220 (OpenDNS)');
		o.value('208.67.222.222', '208.67.222.222 (OpenDNS)');
		o.depends({ dns_mode: 'dns2socks' });
		o.depends({ dns_mode: 'tcp' });
		o.depends({ dns_mode: 'udp' });
		o.depends({ xray_dns_mode: 'udp' });
		o.depends({ xray_dns_mode: 'tcp' });
		o.depends({ singbox_dns_mode: 'udp' });
		o.depends({ singbox_dns_mode: 'tcp' });
		o.depends({ singbox_dns_mode: 'tls' });
		o.depends({ singbox_dns_mode: 'quic' });

		o = s.taboption('DNS', form.Value, 'remote_dns_doh', _('Remote DNS DoH'));
		o.description = _('Format: URL[,IP] (optional IP to map the domain in the URL)');
		o.value('https://1.1.1.1/dns-query', '1.1.1.1 (CloudFlare)');
		o.value('https://1.1.1.2/dns-query', '1.1.1.2 (CloudFlare-Security)');
		o.value('https://8.8.4.4/dns-query', '8.8.4.4 (Google)');
		o.value('https://8.8.8.8/dns-query', '8.8.8.8 (Google)');
		o.value('https://9.9.9.9/dns-query', '9.9.9.9 (Quad9)');
		o.value('https://149.112.112.112/dns-query', '149.112.112.112 (Quad9)');
		o.value('https://208.67.222.222/dns-query', '208.67.222.222 (OpenDNS)');
		o.value('https://dns.adguard.com/dns-query,94.140.14.14', '94.140.14.14 (AdGuard)');
		o.value('https://doh.libredns.gr/dns-query,116.202.176.26', '116.202.176.26 (LibreDNS)');
		o.value('https://doh.libredns.gr/ads,116.202.176.26', '116.202.176.26 (LibreDNS-NoAds)');
		o.default = 'https://1.1.1.1/dns-query';
		o.validate = function(section, value) {
			var cleaned = String(value || '').replace(/\s+/g, '');
			if (cleaned !== '') {
				var parts = cleaned.split(',');
				var ok = true;
				for (var i = 1; i < parts.length; i++) {
					if (parts[i] && !isIpMask4(parts[i]) && !isIpMask6(parts[i]))
						ok = false;
				}
				if (ok)
					return true;
			}
			return tf('%s request address', 'DoH') + ' ' + _('Format must be:') + ' URL,IP';
		};
		o.depends({ xray_dns_mode: 'doh' });
		o.depends({ singbox_dns_mode: 'doh' });
		o.depends({ singbox_dns_mode: 'http3' });

		o = s.taboption('DNS', form.Value, 'remote_dns_client_ip', _('EDNS Client Subnet'));
		o.description = E('div', {}, [
			_('Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).'),
			E('br'),
			_('This feature requires the DNS server to support the Edns Client Subnet (RFC7871).')
		]);
		o.datatype = 'ipaddr';
		o.depends({ dns_mode: 'sing-box' });
		o.depends({ dns_mode: 'xray' });
		o.depends('dns_shunt', 'smartdns');
		o.depends('_node_sel_shunt', '1');

		o = s.taboption('DNS', form.Flag, 'remote_fakedns', 'FakeDNS', _('Use FakeDNS work in the domain that proxy.'));
		o.default = '0';
		o.depends({ dns_mode: 'sing-box', dns_shunt: 'dnsmasq' });
		o.depends({ dns_mode: 'sing-box', dns_shunt: 'chinadns-ng' });
		o.depends({ smartdns_dns_mode: 'sing-box', dns_shunt: 'smartdns' });
		o.depends({ dns_mode: 'xray', dns_shunt: 'dnsmasq' });
		o.depends({ dns_mode: 'xray', dns_shunt: 'chinadns-ng' });
		o.depends({ smartdns_dns_mode: 'xray', dns_shunt: 'smartdns' });
		o.validate = function(section, value) {
			if (String(value) === '1') {
				var mode = dnsMode.formvalue(section);
				if (!mode && smartdnsMode)
					mode = smartdnsMode.formvalue(section);
				var nid = nodeOpt.formvalue(section);
				if (mode && nid) {
					var n = nodeById(nid);
					var ntype = String((n && n.type) || '').toLowerCase();
					if (ntype !== String(mode).toLowerCase() && String(nid).indexOf('socks_') < 0)
						return tf('Node must be \'%s\' type to use FakeDNS.', mode);
				}
			}
			return true;
		};

		var rewriteTtl = s.taboption('DNS', form.Value, 'remote_rewrite_ttl', _('Remote DNS') + ' TTL');
		rewriteTtl.datatype = 'min(1)';
		rewriteTtl.default = '30';
		rewriteTtl.depends({ dns_mode: 'sing-box', dns_shunt: 'dnsmasq' });
		rewriteTtl.depends({ dns_mode: 'sing-box', dns_shunt: 'chinadns-ng' });
		rewriteTtl.depends({ smartdns_dns_mode: 'sing-box', dns_shunt: 'smartdns' });

		o = s.taboption('DNS', form.ListValue, 'chinadns_ng_default_tag', _('Default DNS'));
		o.default = 'none';
		o.value('gfw', _('Remote DNS'));
		o.value('chn', _('Direct DNS'));
		o.value('none', _('Smart, Do not accept no-ip reply from Direct DNS'));
		o.value('none_noip', _('Smart, Accept no-ip reply from Direct DNS'));
		o.description = ul(smartDnsLines());
		o.depends({ dns_shunt: 'chinadns-ng', tcp_proxy_mode: 'proxy', chn_list: 'direct' });

		o = s.taboption('DNS', form.ListValue, 'use_default_dns', _('Default DNS'));
		o.default = 'direct';
		o.value('remote', _('Remote DNS'));
		o.value('direct', _('Direct DNS'));
		o.description = ul(baseDnsLines());
		o.depends({ dns_shunt: 'dnsmasq', tcp_proxy_mode: 'proxy', chn_list: 'direct' });

		if (present(caps.smartdns)) {
			o = s.taboption('DNS', form.ListValue, 'smartdns_default_dns', _('Default DNS'));
			o.default = 'direct';
			o.value('remote', _('Remote DNS'));
			o.value('direct', _('Direct DNS'));
			o.value('auto', _('Auto'));
			o.description = ul(baseDnsLines().concat([
				_('Auto: Prefer mainland China IPs returned by direct DNS and fall back to remote DNS when no usable result is available.')
			]));
			o.depends({ dns_shunt: 'smartdns', tcp_proxy_mode: 'proxy', chn_list: 'direct' });
		}

		o = s.taboption('DNS', form.Flag, 'force_https_soa', _('Force HTTPS SOA'), _('Force queries with qtype 65 to respond with an SOA record.'));
		o.default = '0';
		o.depends({ dns_shunt: 'chinadns-ng' });
		if (present(caps.smartdns))
			o.depends({ dns_shunt: 'smartdns' });

		o = s.taboption('DNS', form.Flag, 'dns_redirect', _('DNS Redirect'), _('Force special DNS server to need proxy devices.'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('DNS', form.Flag, 'flush_set_on_reboot', _('Clear NFTSET on Reboot'), _('Clear NFTSET on service reboot. This may increase reboot time.'));
		o.default = '0';

		o = s.taboption('DNS', form.DummyValue, 'clear_nftset', _('Clear NFTSET'), _('Try this feature if the rule modification does not take effect.'));
		o.renderWidget = function() {
			return E('button', {
				'class': 'cbi-button cbi-button-remove',
				'type': 'button',
				'click': function(ev) {
					ev.preventDefault();
					return pw.call('flush_set', { redirect: '1', reload: '1' }).then(function() {
						window.location.reload();
					});
				}
			}, clearTitle);
		};

		o = s.taboption('Proxy', form.Flag, 'use_direct_list', tf('Use %s', _('Direct List')));
		o.default = '1';
		o = s.taboption('Proxy', form.Flag, 'use_proxy_list', tf('Use %s', _('Proxy List')));
		o.default = '1';
		o = s.taboption('Proxy', form.Flag, 'use_block_list', tf('Use %s', _('Block List')));
		o.default = '1';
		var useGfw = null;
		if (caps.has_gfwlist) {
			useGfw = s.taboption('Proxy', form.Flag, 'use_gfw_list', tf('Use %s', _('GFW List')));
			useGfw.default = '1';
		}
		var chnList = null;
		if (caps.has_chnlist || caps.has_chnroute) {
			chnList = s.taboption('Proxy', form.ListValue, 'chn_list', _('China List'));
			chnList.value('0', _('Close(Not use)'));
			chnList.value('direct', _('Direct Connection'));
			chnList.value('proxy', _('Proxy'));
			chnList.default = 'direct';
		}
		var tcpMode = s.taboption('Proxy', form.ListValue, 'tcp_proxy_mode', 'TCP ' + _('Default Proxy Mode'));
		tcpMode.value('disable', _('No Proxy'));
		tcpMode.value('proxy', _('Proxy'));
		tcpMode.default = 'proxy';
		var udpMode = s.taboption('Proxy', form.ListValue, 'udp_proxy_mode', 'UDP ' + _('Default Proxy Mode'));
		udpMode.value('disable', _('No Proxy'));
		udpMode.value('proxy', _('Proxy'));
		udpMode.default = 'proxy';

		o = s.taboption('Proxy', form.DummyValue, 'switch_mode', '');
		o.render = function() {
			return renderProxySwitch(sid, {
				use_gfw_list: useGfw,
				chn_list: chnList,
				tcp_proxy_mode: tcpMode,
				udp_proxy_mode: udpMode
			});
		};

		if (transparent) {
			o = s.taboption('Proxy', form.Flag, 'localhost_proxy', _('Localhost Proxy'), _('When selected, localhost can transparent proxy.'));
			o.default = '1';
			o.rmempty = false;
			o = s.taboption('Proxy', form.Flag, 'client_proxy', _('Client Proxy'), _('When selected, devices in LAN can transparent proxy. Otherwise, it will not be proxy. But you can still use access control to allow the designated device to proxy.'));
			o.default = '1';
			o.rmempty = false;
		}
		else {
			o = s.taboption('Proxy', form.DummyValue, 'localhost_proxy', _('Localhost Proxy'));
			o.renderWidget = function() { return missingProxyWidget(); };
			o = s.taboption('Proxy', form.DummyValue, 'client_proxy', _('Client Proxy'));
			o.renderWidget = function() { return missingProxyWidget(); };
		}

		o = s.taboption('Proxy', form.DummyValue, '_proxy_tips', '　');
		o.renderWidget = function() {
			return E('a', {
				'class': 'pw-warn',
				'href': pw.pageUrl('acl')
			}, _('Want different devices to use different proxy modes/ports/nodes? Please use access control.'));
		};

		o = s.taboption('log', form.Flag, 'log_node', _('Enable Node Log'));
		o.default = '0';
		o.rmempty = false;
		o = s.taboption('log', form.ListValue, 'loglevel', _('Log Level'));
		o.default = 'warn';
		o.value('debug', 'Debug');
		o.value('info', 'Info');
		o.value('warn', 'Warning');
		o.value('error', 'Error');
		o = s.taboption('log', form.DummyValue, '_node_log', _('Log File'));
		o.depends('log_node', '1');
		logFileOption(o, LOG_GLOBAL, logGlobal, function() {
			return openLog(pw.get('get_redir_log', { id: 'default' }));
		});

		o = s.taboption('log', form.Flag, 'log_chinadns_ng', _('Enable') + ' ChinaDNS-NG ' + _('Log'));
		o.default = '0';
		o.rmempty = false;
		o.depends('dns_shunt', 'chinadns-ng');
		o = s.taboption('log', form.DummyValue, '_chinadns_ng_log', _('Log File'));
		o.depends('log_chinadns_ng', '1');
		logFileOption(o, LOG_CHINA, logChina, function() {
			return openLog(pw.get('get_chinadns_log', { flag: 'default' }));
		});

		if (present(caps.smartdns)) {
			o = s.taboption('log', form.Flag, 'log_smartdns', _('Enable') + ' SmartDNS ' + _('Log'));
			o.default = '0';
			o.rmempty = false;
			o.depends('dns_shunt', 'smartdns');
			o = s.taboption('log', form.ListValue, 'smartdns_log_level', 'SmartDNS ' + _('Log Level'));
			o.default = 'error';
			o.value('fatal', 'Fatal');
			o.value('error', 'Error');
			o.value('warn', 'Warning');
			o.value('notice', 'Notice');
			o.value('info', 'Info');
			o.value('debug', 'Debug');
			o.depends('log_smartdns', '1');
			o = s.taboption('log', form.Value, 'smartdns_log_size', _('Log Size') + ' (MB)');
			o.default = '1';
			o.datatype = 'and(uinteger,min(1))';
			o.depends('log_smartdns', '1');
			o = s.taboption('log', form.DummyValue, '_smartdns_log', _('Log File'));
			o.depends('log_smartdns', '1');
			logFileOption(o, LOG_SMART, logSmart, function() {
				return openLog(pw.get('get_smartdns_log'));
			});
			if (caps.has_smartdns_ui) {
				o = s.taboption('log', form.Flag, 'smartdns_ui', 'SmartDNS ' + _('Enable WebUI'));
				o.default = '0';
				o.rmempty = false;
				o.depends('dns_shunt', 'smartdns');
				var uiPort = s.taboption('log', form.Value, 'smartdns_ui_port', _('WebUI Port'));
				uiPort.default = '9880';
				uiPort.datatype = 'range(1,65535)';
				uiPort.depends('smartdns_ui', '1');
				o = s.taboption('log', form.Value, 'smartdns_ui_data_dir', _('WebUI Database Directory'));
				o.default = TMP + '_tmp/smartdns';
				o.depends('smartdns_ui', '1');
				o.validate = function(section, value) {
					value = String(value == null ? '' : value).replace(/^\s+|\s+$/g, '');
					if (value.charAt(0) !== '/' || /\s/.test(value))
						return _('An absolute path without spaces is required.');
					return true;
				};
				o = s.taboption('log', form.Value, 'smartdns_ui_log_max_age', _('WebUI Log Retention Days'));
				o.default = '7';
				o.datatype = 'and(uinteger,min(1))';
				o.depends('smartdns_ui', '1');
				o = s.taboption('log', form.DummyValue, '_smartdns_ui_link', 'WebUI');
				o.depends('smartdns_ui', '1');
				o.renderWidget = function() {
					return E('input', {
						'class': 'btn cbi-button cbi-button-apply',
						'type': 'button',
						'value': _('Open WebUI'),
						'click': function(ev) {
							ev.preventDefault();
							var port = parseInt(uiPort.formvalue(sid), 10);
							if (!(port >= 1 && port <= 65535))
								port = 9880;
							var host = window.location.hostname;
							if (host.indexOf(':') !== -1 && host.charAt(0) !== '[')
								host = '[' + host + ']';
							window.open('http://' + host + ':' + port, '_blank', 'noopener,noreferrer');
						}
					});
				};
			}
		}

		o = s.taboption('log', form.DummyValue, '_log_tips', '　');
		o.renderWidget = function() {
			return E('font', { 'color': 'red' }, _('It is recommended to disable logging during regular use to reduce system overhead.'));
		};

		o = s.taboption('faq', form.DummyValue, '_faq', '');
		o.render = function() { return renderFaq(); };

		o = s.taboption('maintain', form.DummyValue, '_backup', '');
		o.render = function() { return renderBackup(); };

		var socksAnchor = s.taboption('socks', form.DummyValue, '_socks_anchor', '');
		socksAnchor.render = function() { return E('div', { 'id': 'pw-socks-anchor' }); };

		o = s.taboption('Main', form.Flag, 'socks_enabled', 'Socks ' + _('Main switch'));
		o.rmempty = false;

		var shuntNodeId = showShunt ? nodeIdOf(loadedObj) : '';
		function mirror(option, uciName, asFlag) {
			option.cfgvalue = function() {
				return uci.get('passwall', shuntNodeId, uciName);
			};
			option.write = function(section, value) {
				uci.unset('passwall', section, option.option);
				if (nodeOpt.formvalue(section) !== shuntNodeId)
					return;
				if (asFlag) {
					if (String(value) === '1')
						uci.set('passwall', shuntNodeId, uciName, '1');
					else
						uci.unset('passwall', shuntNodeId, uciName);
					return;
				}
				if (value == null || value === '')
					uci.unset('passwall', shuntNodeId, uciName);
				else
					uci.set('passwall', shuntNodeId, uciName, value);
			};
			option.remove = function(section) {
				uci.unset('passwall', section, option.option);
				if (nodeOpt.formvalue(section) !== shuntNodeId)
					return;
				uci.unset('passwall', shuntNodeId, uciName);
			};
			option.depends('node', shuntNodeId);
		}

		if (showShunt) {
			if (loadedObj.type === 'Xray') {
				o = s.taboption('Shunt', form.ListValue, 'domainStrategy', _('Domain Strategy'));
				o.value('AsIs');
				o.value('IPIfNonMatch');
				o.value('IPOnDemand');
				o.default = 'IPOnDemand';
				o.description = E('div', {}, [
					E('br'),
					ul([
						_("'AsIs': Only use domain for routing. Default value."),
						_("'IPIfNonMatch': When no rule matches current domain, resolves it into IP addresses (A or AAAA records) and try all rules again."),
						_("'IPOnDemand': As long as there is a IP-based rule, resolves the domain into IP immediately.")
					])
				]);
				mirror(o, 'domainStrategy', false);
				o = s.taboption('Shunt', form.ListValue, 'domainMatcher', _('Domain matcher'));
				o.value('hybrid');
				o.value('linear');
				mirror(o, 'domainMatcher', false);
			}
			var fakeTitle = _('Use FakeDNS work in the domain that proxy.') + '\n' +
				_('Suitable scenarios for let the node servers get the target domain names.') + '\n' +
				_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.');
			o = s.taboption('Shunt', form.Flag, 'fakedns', E('span', {}, [
				E('a', { 'style': 'color:#FF8C00' }, 'FakeDNS'),
				' ' + _('Main switch')
			]), E('div', {}, [
				_('Use FakeDNS work in the domain that proxy.'),
				E('br'),
				_('Suitable scenarios for let the node servers get the target domain names.'),
				E('br'),
				_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.')
			]));
			mirror(o, 'fakedns', true);

			var shuntGroup = s.taboption('Shunt', form.ListValue, 'shunt_group', _('Shunt Rule Group'));
			shuntGroup.value('', _('default'));
			var seenGroups = {};
			(uci.sections('passwall', 'shunt_rules') || []).forEach(function(rule) {
				if (rule.group && !seenGroups[rule.group]) {
					seenGroups[rule.group] = true;
					shuntGroup.value(rule.group, rule.group);
				}
			});
			mirror(shuntGroup, 'shunt_group', false);
			shuntGroup.onchange = function(ev, section_id, value) {
				if (!value)
					uci.unset('passwall', shuntNodeId, 'shunt_group');
				else
					uci.set('passwall', shuntNodeId, 'shunt_group', value);
				uci.unset('passwall', section_id, 'shunt_group');
				uci.save().then(function() {
					window.location.reload();
				});
			};
		}

		function appendNodeLists(items) {
			var order = ['socks_list', 'normal_list', 'balancing_list', 'urltest_list', 'iface_list'];
			var seen = { 'shunt_list': true };
			order.forEach(function(key) { seen[key] = true; });
			function pushList(list) {
				(list || []).forEach(function(v) {
					items.push({
						value: v.id,
						label: v.remark,
						group: (v.group && v.group !== '') ? v.group : _('default')
					});
				});
			}
			order.forEach(function(key) { pushList(nodeList[key]); });
			Object.keys(nodeList).forEach(function(key) {
				if (seen[key])
					return;
				pushList(nodeList[key]);
			});
		}

		var shuntTable = null;
		if (showShunt) {
			var groupVal = String(uci.get('passwall', shuntNodeId, 'shunt_group') || '').toLowerCase();
			var rules = [];
			(uci.sections('passwall', 'shunt_rules') || []).forEach(function(e) {
				if (String(e.group || '').toLowerCase() === groupVal) {
					rules.push({
						id: e['.name'],
						remarks: e.remarks || e['.name'],
						nodeOption: e['.name'],
						nodeDefault: '',
						fakeOption: e['.name'] + '_fakedns',
						proxyOption: e['.name'] + '_proxy_tag',
						isDefault: false
					});
				}
			});
			rules.push({
				id: '.default',
				remarks: _('Default'),
				nodeOption: 'default_node',
				nodeDefault: '_direct',
				fakeOption: 'default_fakedns',
				proxyOption: 'default_proxy_tag',
				isDefault: true
			});
			var normalIds = {};
			(nodeList.normal_list || []).forEach(function(n) { normalIds[n.id] = true; });
			var preTitle = _('Set the node to be used as a pre-proxy.') + '\n' +
				_('Each rule has a separate switch that controls whether this rule uses the pre-proxy or not.');
			var fakeHead = _('Use FakeDNS work in the domain that proxy.') + '\n' +
				_('Suitable scenarios for let the node servers get the target domain names.') + '\n' +
				_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.');
			var body = [ E('tr', { 'class': 'cbi-section-table-titles' }, [
				E('th', { 'class': 'cbi-section-table-cell' }, _('Rule')),
				E('th', { 'class': 'cbi-section-table-cell' }, _('Node')),
				E('th', { 'class': 'cbi-section-table-cell' }, E('a', { 'style': 'color:#FF8C00', 'title': fakeHead }, 'FakeDNS')),
				E('th', { 'class': 'cbi-section-table-cell' }, E('a', { 'class': 'pw-warn', 'title': preTitle }, _('Preproxy')))
			])];
			rules.forEach(function(rule) {
				var curNode = uci.get('passwall', shuntNodeId, rule.nodeOption);
				if (curNode == null || curNode === '')
					curNode = rule.nodeDefault;
				var curProxy = uci.get('passwall', shuntNodeId, rule.proxyOption) || '';
				var curFake = uci.get('passwall', shuntNodeId, rule.fakeOption) === '1';
				var nodeItems = [
					{ value: '', label: _('Close (Not use)'), group: '' }
				];
				if (!rule.isDefault)
					nodeItems.push({ value: '_default', label: _('Use default node'), group: '' });
				nodeItems.push({ value: '_direct', label: _('Direct Connection'), group: '' });
				nodeItems.push({ value: '_blackhole', label: _('Blackhole (Block)'), group: '' });
				appendNodeLists(nodeItems);
				var proxyItems = [ { value: '', label: _('Close (Not use)'), group: '' } ];
				appendNodeLists(proxyItems);
				var nodeSel = buildSelect('pw-shunt-node-' + rule.id, nodeItems, curNode);
				var proxySel = buildSelect('pw-shunt-proxy-' + rule.id, proxyItems, curProxy);
				var fake = E('input', { 'type': 'checkbox', 'class': 'cbi-input-checkbox' });
				if (curFake)
					fake.checked = true;
				nodeSel.setAttribute('data-shunt-option', rule.nodeOption);
				proxySel.setAttribute('data-shunt-option', rule.proxyOption);
				fake.setAttribute('data-shunt-option', rule.fakeOption);
				fake.setAttribute('data-shunt-flag', '1');
				function applyVisibility(persist) {
					var val = nodeSel.value;
					var showFake = !(val === '' || val === '_direct');
					fake.style.display = showFake ? '' : 'none';
					if (!showFake)
						fake.checked = false;
					var showProxy = !(!val || val.charAt(0) === '_' || val.indexOf('socks_') === 0 || !normalIds[val]);
					proxySel.style.display = showProxy ? '' : 'none';
					if (!showProxy)
						proxySel.value = '';
					if (persist && !showFake)
						uci.unset('passwall', shuntNodeId, rule.fakeOption);
					if (persist && !showProxy)
						uci.unset('passwall', shuntNodeId, rule.proxyOption);
				}
				nodeSel.addEventListener('change', function() {
					if (nodeSel.value === '')
						uci.unset('passwall', shuntNodeId, rule.nodeOption);
					else
						uci.set('passwall', shuntNodeId, rule.nodeOption, nodeSel.value);
					applyVisibility(true);
				});
				proxySel.addEventListener('change', function() {
					if (!proxySel.value)
						uci.unset('passwall', shuntNodeId, rule.proxyOption);
					else
						uci.set('passwall', shuntNodeId, rule.proxyOption, proxySel.value);
				});
				fake.addEventListener('change', function() {
					if (fake.checked)
						uci.set('passwall', shuntNodeId, rule.fakeOption, '1');
					else
						uci.unset('passwall', shuntNodeId, rule.fakeOption);
				});
				applyVisibility(false);
				var ruleCell = rule.isDefault
					? E('span', { 'class': 'pw-warn' }, rule.remarks)
					: E('a', { 'href': pw.pageUrl('shunt_rules', rule.id), 'target': '_blank' }, rule.remarks);
				var edit = E('a', {
					'href': '#',
					'click': function(ev) {
						ev.preventDefault();
						var val = nodeSel.value;
						if (!val || val.indexOf('tcp') === 0 || val.indexOf('_default') === 0 || val.indexOf('_direct') === 0 || val.indexOf('_blackhole') === 0)
							return;
						window.location.href = (val.indexOf('socks_') === 0)
							? pw.pageUrl('socks_config', val)
							: pw.pageUrl('node_config', val);
					}
				}, _('Edit'));
				body.push(E('tr', { 'class': 'cbi-section-table-row' }, [
					E('td', { 'class': 'cbi-section-table-cell' }, ruleCell),
					E('td', { 'class': 'cbi-section-table-cell' }, [ nodeSel, ' ', edit ]),
					E('td', { 'class': 'cbi-section-table-cell' }, fake),
					E('td', { 'class': 'cbi-section-table-cell' }, proxySel)
				]));
			});
			shuntTable = E('div', { 'id': 'cbi-passwall-shunt_option_list', 'data-node-id': shuntNodeId, 'class': 'cbi-section' }, [
				E('table', { 'class': 'table cbi-section-table' }, body)
			]);
		}

		var s2 = m.section(form.GridSection, 'socks', _('Socks Config'));
		s2.anonymous = true;
		s2.addremove = true;
		s2.sortable = true;
		s2.nodescriptions = true;
		s2.extedit = pw.pageUrl('socks_config') + '/%s';
		s2.handleAdd = function() {
			var uid = 'socks_' + pw.rand(5);
			var n = 1;
			(uci.sections('passwall', 'socks') || []).forEach(function() { n++; });
			var configName = this.uciconfig || this.map.config;
			this.uci.add(configName, 'socks', uid);
			this.uci.set(configName, uid, 'port', String(1080 + n));
			this.uci.set(configName, uid, 'http_port', '0');
			return this.map.save().then(function() {
				window.location.href = pw.pageUrl('socks_config', uid);
			});
		};
		s2.handleRemove = function(section_id, ev) {
			var nodeSecs = uci.sections('passwall', 'nodes') || [];
			var newNode = nodeSecs.length ? nodeSecs[0]['.name'] : '';
			if ((uci.get('passwall', sid, 'node') || '') === section_id)
				uci.set('passwall', sid, 'node', newNode);
			(uci.sections('passwall', 'acl_rule') || []).forEach(function(rule) {
				if (rule.node === section_id)
					uci.set('passwall', rule['.name'], 'node', 'default');
			});
			nodeSecs.forEach(function(node) {
				var listName = null;
				if (node.urltest_node != null && node.urltest_node !== '')
					listName = 'urltest_node';
				else if (node.balancing_node != null && node.balancing_node !== '')
					listName = 'balancing_node';
				if (listName) {
					var list = uci.get('passwall', node['.name'], listName) || [];
					if (!Array.isArray(list))
						list = [list];
					var kept = [];
					var changed = false;
					list.forEach(function(item) {
						if (item === section_id)
							changed = true;
						else
							kept.push(item);
					});
					if (changed)
						uci.set('passwall', node['.name'], listName, kept);
				}
				if (node.fallback_node === section_id)
					uci.unset('passwall', node['.name'], 'fallback_node');
			});
			return form.GridSection.prototype.handleRemove.call(this, section_id, ev);
		};

		o = s2.option(form.Flag, 'enabled', _('Enable'));
		o.default = '1';
		o.rmempty = false;
		o.modalonly = false;

		var socksNode = s2.option(form.ListValue, 'node', _('Socks Node'));
		socksNode.modalonly = false;

		o = s2.option(form.DummyValue, 'now_node', _('Current Node'));
		o.modalonly = false;
		o.renderWidget = function(section_id) {
			var holder = E('div', { 'id': 'pw-now-' + section_id, 'data-socks-id': section_id });
			var cache = parseCache(cacheText);
			var nid = cache[section_id];
			remarkNode(holder, nid ? (remarks[nid] || nid) : '');
			return holder;
		};

		o = s2.option(form.DummyValue, 'port_status', _('Port Status'));
		o.modalonly = false;
		o.renderWidget = function(section_id) {
			var socks = uci.get('passwall', section_id, 'port') || '0';
			var http = uci.get('passwall', section_id, 'http_port') || '0';
			return E('div', { 'class': '_socks_status', 'socks_id': section_id }, [
				E('span', { 'class': '_socks' }),
				' SOCKS: ' + socks,
				E('br'),
				E('span', { 'class': '_http' }),
				' HTTP: ' + http
			]);
		};

		var mainItems = [ { value: '', label: _('Close'), group: '' } ];
		if (hasCore) {
			(nodeList.socks_list || []).forEach(function(v) {
				mainItems.push({ value: v.id, label: v.remark, group: groupName(v) });
			});
		}
		if (hasNormal) {
			nodes.forEach(function(v) {
				var id = nodeIdOf(v);
				if (v.protocol === '_shunt') {
					if (!hasCore)
						return;
					shuntIds[id] = true;
					shuntSel.depends({ node: id });
					if (v.type === 'Xray')
						xrayDns.depends({ node: id });
					else {
						singDns.depends({ node: id });
						rewriteTtl.depends({ node: id });
					}
				}
				mainItems.push({ value: id, label: v.remark, group: groupName(v) });
			});
		}
		groupedNode(nodeOpt, mainItems, { flag: setShuntFlag });
		nodeOpt.onchange = function(ev, section_id, value) {
			if (shuntIds[value] && value !== loadedNode) {
				uci.set('passwall', section_id, 'node', value);
				uci.save().then(function() {
					window.location.reload();
				});
			}
		};

		var socksItems = [];
		if (hasNormal) {
			nodes.forEach(function(v) {
				if (v.type === 'Socks' && !hasCore)
					return;
				socksItems.push({ value: nodeIdOf(v), label: v.remark, group: groupName(v) });
			});
		}
		groupedNode(socksNode, socksItems, null);

		this._flushShunt = function() {
			if (!shuntTable)
				return;
			var nodeId = shuntTable.getAttribute('data-node-id');
			if (nodeOpt.formvalue(sid) !== nodeId)
				return;
			shuntTable.querySelectorAll('[data-shunt-option]').forEach(function(el) {
				var key = el.getAttribute('data-shunt-option');
				if (el.getAttribute('data-shunt-flag')) {
					if (el.checked)
						uci.set('passwall', nodeId, key, '1');
					else
						uci.unset('passwall', nodeId, key);
				}
				else if (!el.value) {
					uci.unset('passwall', nodeId, key);
				}
				else {
					uci.set('passwall', nodeId, key, el.value);
				}
			});
		};

		var refreshDnsLog = function() {};
		dnsShunt.onchange = function() { refreshDnsLog(); };

		function qid(scope, id) {
			if (!scope)
				return null;
			if (scope.id === id)
				return scope;
			return scope.querySelector('[id="' + String(id).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"]');
		}

		var self = this;
		return m.render().then(function(formNode) {
			rootKids.push(formNode);
			var root = E('div', {}, rootKids);
			var tab = qid(root, 'container.passwall.' + sid + '.socks');
			var grid = qid(root, 'cbi-passwall-socks');
			var socksEnabled = qid(root, 'cbi-passwall-' + sid + '-socks_enabled');
			if (tab && socksEnabled)
				tab.appendChild(socksEnabled);
			if (tab && grid)
				tab.appendChild(grid);
			if (shuntTable) {
				var shuntBox = qid(root, 'container.passwall.' + sid + '.Shunt');
				if (shuntBox)
					shuntBox.appendChild(shuntTable);
			}
			var dnsEl = qid(root, dnsShunt.cbid(sid));
			refreshDnsLog = function() {
				if (!dnsEl || !dnsEl.parentNode)
					return;
				var old = dnsEl.parentNode.querySelector('a.dns-log-link');
				if (old)
					old.parentNode.removeChild(old);
				var val = dnsShunt.formvalue(sid);
				if (val !== 'chinadns-ng' && val !== 'smartdns')
					return;
				dnsEl.parentNode.appendChild(E('a', {
					'href': '#',
					'class': 'dns-log-link',
					'style': 'margin-left:10px',
					'click': function(ev) {
						ev.preventDefault();
						var cur = dnsShunt.formvalue(sid);
						if (cur === 'smartdns')
							openLog(pw.get('get_smartdns_log'));
						else
							openLog(pw.get('get_chinadns_log', { flag: 'default' }));
					}
				}, _('Log')));
			};
			refreshDnsLog();
			if (dnsEl)
				dnsEl.addEventListener('change', refreshDnsLog);

			function attachNodeLinks(select, mode, socksId) {
				if (!select || !select.parentNode || select.parentNode.querySelector('.node-actions'))
					return;
				var box = E('div', {
					'class': 'node-actions',
					'style': 'display:inline-flex;align-items:center;gap:4px;flex-wrap:wrap;margin-left:4px;'
				}, [
					E('a', {
						'href': '#',
						'click': function(ev) {
							ev.preventDefault();
							var val = select.value;
							if (!val || val.indexOf('tcp') === 0 || val.indexOf('_default') === 0 || val.indexOf('_direct') === 0 || val.indexOf('_blackhole') === 0)
								return;
							window.location.href = (val.indexOf('socks_') === 0)
								? pw.pageUrl('socks_config', val)
								: pw.pageUrl('node_config', val);
						}
					}, _('Edit')),
					E('a', {
						'href': '#',
						'click': function(ev) {
							ev.preventDefault();
							if (mode === 'socks')
								openLog(pw.get('get_socks_log', { name: socksId }));
							else
								openLog(pw.get('get_redir_log', { id: 'default' }));
						}
					}, _('Log'))
				]);
				select.parentNode.appendChild(box);
			}
			attachNodeLinks(qid(root, nodeOpt.cbid(sid)), 'global');
			(uci.sections('passwall', 'socks') || []).forEach(function(sec) {
				attachNodeLinks(qid(root, 'cbid.passwall.' + sec['.name'] + '.node'), 'socks', sec['.name']);
			});

			var directField = qid(root, 'cbi-passwall-' + sid + '-smartdns_direct_dns');
			if (directField) {
				var updateDirect = function() {
					var list = directField.querySelector('.cbi-dynlist');
					if (!list)
						return;
					var inputs = list.querySelectorAll('.item > input[type="hidden"]');
					var hasDns = false;
					for (var i = 0; i < inputs.length; i++) {
						if (String(inputs[i].value || '').trim() !== '')
							hasDns = true;
					}
					var text = hasDns ? _('-- Please choose --') : _('Auto');
					var placeholder = list.querySelector('.add-item .cbi-dropdown > ul > li[placeholder]');
					if (placeholder && placeholder.textContent !== text)
						placeholder.textContent = text;
					var input = list.querySelector('.add-item > input[type="text"]');
					if (input)
						input.placeholder = hasDns ? '' : _('Auto');
				};
				new MutationObserver(updateDirect).observe(directField, { childList: true, subtree: true });
				updateDirect();
			}

			poll.add(function() {
				return Promise.all([
					pw.get('index_status'),
					pw.get('get_now_use_node'),
					fs.read(CACHE_VAR).catch(function() { return ''; })
				]).then(function(res) {
					paintIndex(res[0]);
					paintNowNode(res[1], remarks);
					paintSocksRuntime(parseCache(res[2]), remarks);
					return paintSocksPorts();
				});
			}, 5);

			self.map = m;
			return root;
		});
	},

	handleSave: function(ev) {
		if (typeof this._flushShunt === 'function')
			this._flushShunt();
		return this.super('handleSave', [ev]);
	}
});
