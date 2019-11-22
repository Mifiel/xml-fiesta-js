const path = require('path');
const projectRoot = path.resolve(__dirname, './');

module.exports = {
  instrumentor: 'istanbul',
  basePath: projectRoot,
  exclude: [
    '/spec',
    '/node_modules',
    '/.git',
    '/src/xml-fiesta',
    '/Gruntfile',
    '/coverage-reporter'
  ],
  initAll: true
}
