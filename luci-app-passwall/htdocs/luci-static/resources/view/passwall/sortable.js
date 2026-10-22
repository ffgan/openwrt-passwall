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
			var moved = false;

			function originOf(target) {
				if (!target)
					return null;
				if (target.nodeType === 1)
					return target;
				return target.parentElement || target.parentNode || null;
			}

			function finish() {
				if (!dragging)
					return;
				dragging.classList.remove(ghostClass);
				host.classList.remove('pw-sorting');
				dragging = null;
				if (moved && typeof options.onEnd === 'function')
					options.onEnd();
				moved = false;
			}

			function down(ev) {
				if (ev.button != null && ev.button !== 0)
					return;
				var origin = originOf(ev.target);
				if (handle && !(origin && origin.closest && origin.closest(handle)))
					return;
				var row = rowFrom(host, selector, origin);
				if (!row)
					return;
				dragging = row;
				moved = false;
				row.classList.add(ghostClass);
				host.classList.add('pw-sorting');
				if (ev.cancelable)
					ev.preventDefault();
			}

			function move(ev) {
				if (!dragging)
					return;
				var target = null;
				var placeAfter = false;
				var child = host.firstElementChild || host.firstChild;
				while (child) {
					if (child !== dragging && child.nodeType === 1 && matches(child, selector)) {
						var rect = child.getBoundingClientRect();
						var mid = rect.top + rect.height / 2;
						if (ev.clientY < mid) {
							target = child;
							placeAfter = false;
							break;
						}
						target = child;
						placeAfter = true;
					}
					child = child.nextElementSibling || child.nextSibling;
				}
				if (!target)
					return;
				var next = placeAfter ? target.nextSibling : target;
				if (next === dragging)
					return;
				host.insertBefore(dragging, next);
				moved = true;
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
