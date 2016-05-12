path = require('path')
coffeeCoverage = require('coffee-coverage')

projectRoot = path.resolve(__dirname, './')
coverageVar = coffeeCoverage.findIstanbulVariable()
writeOnExit = (projectRoot + '/coverage/coverage-coffee.json')

coffeeCoverage.register {
  instrumentor: 'istanbul'
  basePath: projectRoot
  exclude: [
    '/spec'
    '/node_modules'
    '/.git'
    '/src/xml-fiesta'
    '/Gruntfile'
    '/coverage-reporter'
  ]
  coverageVar: coverageVar
  writeOnExit: writeOnExit
  initAll: true
}
