'use strict';

(function(root) {
	if (root.Sortable && root.Sortable.__passwall)
		return;

	function matches(el, selector) {
		if (!el || el.nodeType !== 1)
			return false;
		if (!selector)
			return true;
		var fn = el.matches || el.msMatchesSelector;
		return fn ? fn.call(el, selector) : false;
	}

	function rowFrom(host, selector, node) {
		while (node && node !== host) {
			if (node.parentNode === host && matches(node, selector))
				return node;
			node = node.parentNode;
		}
		return null;
	}

	root.Sortable = {
		__passwall: true,
		create: function(host, options) {
			options = options || {};
			var selector = options.draggable || null;
			var handle = options.handle || null;
			var ghostClass = options.ghostClass || 'dragging-row';
			var dragging = null;

			function finish() {
				if (!dragging)
					return;
				dragging.classList.remove(ghostClass);
				host.classList.remove('pw-sorting');
				dragging = null;
				if (typeof options.onEnd === 'function')
					options.onEnd();
			}

			function down(ev) {
				if (ev.button != null && ev.button !== 0)
					return;
				if (handle && !(ev.target && ev.target.closest && ev.target.closest(handle)))
					return;
				var row = rowFrom(host, selector, ev.target);
				if (!row)
					return;
				dragging = row;
				row.classList.add(ghostClass);
				host.classList.add('pw-sorting');
				if (ev.cancelable)
					ev.preventDefault();
			}

			function move(ev) {
				if (!dragging)
					return;
				var point = document.elementFromPoint(ev.clientX, ev.clientY);
				var over = rowFrom(host, selector, point);
				if (!over || over === dragging)
					return;
				var rect = over.getBoundingClientRect();
				var after = ev.clientY > rect.top + rect.height / 2;
				if (after) {
					if (over.nextSibling !== dragging)
						host.insertBefore(dragging, over.nextSibling);
				}
				else if (over !== dragging.nextSibling) {
					host.insertBefore(dragging, over);
				}
			}

			host.addEventListener('pointerdown', down);
			document.addEventListener('pointermove', move);
			document.addEventListener('pointerup', finish);
			document.addEventListener('pointercancel', finish);

			return {
				option: function() {},
				destroy: function() {
					finish();
					host.removeEventListener('pointerdown', down);
					document.removeEventListener('pointermove', move);
					document.removeEventListener('pointerup', finish);
					document.removeEventListener('pointercancel', finish);
				}
			};
		}
	};
})(window);
