'use strict';
'require view';
'require poll';
'require view.passwall.tools as pw';

return view.extend({
	render: function() {
		var textarea = E('textarea', {
			'id': 'log_textarea',
			'class': 'cbi-input-textarea',
			'style': 'width:100%;margin-top:10px',
			'rows': 40,
			'wrap': 'off',
			'readonly': 'readonly'
		});

		var first = true;
		function scrollToBottom() {
			textarea.scrollTop = textarea.scrollHeight;
		}

		poll.add(function() {
			return pw.get('get_log').then(function(text) {
				var body = (typeof text === 'string') ? text : '';
				var wasBottom = (textarea.scrollTop + textarea.clientHeight >= textarea.scrollHeight - 10);
				textarea.value = body;
				if (first) {
					scrollToBottom();
					first = false;
				}
				else if (wasBottom) {
					scrollToBottom();
				}
			});
		}, 5);

		return E('div', { 'class': 'cbi-section' }, [
			E('button', {
				'class': 'btn cbi-button cbi-button-remove',
				'click': function() {
					return pw.get('clear_log').then(function() {
						textarea.value = '';
						scrollToBottom();
					});
				}
			}, _('Clear logs')),
			textarea
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
