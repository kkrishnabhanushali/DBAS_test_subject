'use strict';

document.addEventListener('DOMContentLoaded', () => {
  if (typeof Dashboard !== 'undefined') {
    const dashboard = new Dashboard();
    dashboard.init();
  }
});
